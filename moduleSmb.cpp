#include	"header.h"
#include	"utils/md4.h"
#include	"utils/includeMD5.h"

#define	SIZE_NTLMSSP_CHALLENGE	8	/* Taille d'un challenge NTLMSSP */
#define	SIZE_NTLMSSP_HASH	16	/* Taille d'un hash NTLMSSP */
#define	SIZE_NTLMSSP_DATA_MAX	1024	/* Taille max des infos */
#define	TYPE_NTLMSSP_CHALLENGE	0x0002	/* Identifiant des challenge NTLMSSP */
#define	TYPE_NTLMSSP_AUTH	0x0003	/* Identifiant des reponses aux challenges NTLMSSP */

/**
** \struct sIdentifierNTLMSSP
** \brief Entete NTLMSSP
*/
struct	sIdentifierNTLMSSP
{
	/** Magic number ("NTLMSSP\0") */
	char		magic[8];
	/** Type de trame (TLMSSP_CHALLENGE ou TLMSSP_AUTH) */
	uint32_t	type;
} __attribute__ ((packed));

/**
** \struct sNTLMStringInfo
** \brief Structure contenant les infos d'une chaine (ou d'un buffer) dans une trame NTLM
*/
struct	sNTLMStringInfo
{
	/** Taille de la chaine en octets */
	uint16_t	length;
	/** Taille maximum de la chaine en octets */
	uint16_t	maxLen;
	/** Offset du debut de la chaine par rapport au debut de la trame NTLM */
	uint32_t	offset;
} __attribute__ ((packed));

/**
** \struct sInfoChallenge
** \brief Info d'un challenge NTLMv2
*/
class	sInfoChallenge
{
public:
	/** Nom de la cible (le serveur) */
	std::string	targetName;
	/** Flags du challenge */
	uint32_t	negociateFlags;
	/** Challenge NTMLv2 */
	unsigned char	challenge[SIZE_NTLMSSP_CHALLENGE];
};

/**
** \struct sInfoResponse
** \brief Info d'une reponse a un challenge NTLMv2
*/
class	sInfoResponse
{
public:
	/** Hash de reponse au challenge */
	unsigned char	ntlmHash[SIZE_NTLMSSP_HASH];
	/** Blob ayant servi a generer la reponse */
	unsigned char	info[SIZE_NTLMSSP_DATA_MAX];
	/** Taille du blob */
	unsigned long	infoSize;
	/** Nom de domaine de la cible (le serveur) */
	std::string	domainName;
	/** Nom d'utilisateur */
	std::string	userName;
	/** Hostname de l'utilisateur */
	std::string	hostName;
};



static unsigned long	searchNTLMSSPChallenge(std::map<std::string, sInfoChallenge> &dst,
						std::map<unsigned long, sInfoMem*>::const_iterator &itSeg);
static unsigned long	searchNTLMSSPResponse(std::map<std::string, sInfoResponse> &dst,
					std::map<unsigned long, sInfoMem*>::const_iterator &itSeg);
static void	NTLMHashStr(unsigned char *dst, const char *str);
static void	NTMLv2Hash(unsigned char *dst, const char *target, const char *username, const char *password);
static void	LMv2Response(unsigned char *dst, const unsigned char *hash,
				const unsigned char *blob, unsigned long blobSize,
				const unsigned char *challenge);



/**
** \fn unsigned long moduleSmbExec(sInfoProcess &infoProcess, const sUserParam &param)
** \brief Extrait les challenges/responses NTMLv2 des segments RW
**
** \param infoProcess Structure contenant les infos du processus a analyser
** \param param Structure contenant les options utilisateurs
** \return Retourne le nombre de challenge/responses extraits
*/
unsigned long	moduleSmbExec(sInfoProcess &infoProcess, const sUserParam &param)
{
	unsigned long				nbsResult;
	unsigned long				findResultInSegment;
	std::map<std::string, sInfoChallenge>	listChallenge;
	std::map<std::string, sInfoResponse>	listResponse;
	std::map<std::string, std::string>	mapHashAndPass;
	int					ok;

	/* Pour tout les segments */
	nbsResult = 0;
	for (std::map<unsigned long, sInfoMem*>::const_iterator itSeg=infoProcess.listSeg.begin();
	     itSeg!=infoProcess.listSeg.end();
	     itSeg++)
	{
		findResultInSegment = 0;
		if ( ((itSeg->second->flags & INFOMEM_FLAG_R) == INFOMEM_FLAG_R) &&
		     ((itSeg->second->flags & INFOMEM_FLAG_W) == INFOMEM_FLAG_W) )
		{
			/* Cherche les challenge/response dans le segment */
			searchNTLMSSPChallenge(listChallenge, itSeg);
			searchNTLMSSPResponse(listResponse, itSeg);
			findResultInSegment = listChallenge.size() + listResponse.size();
		}

		/* Cree le fichier de dump si besoin est */
		if ((findResultInSegment > 0) && (param.dump != 0))
		{
			saveSegmentToFile(infoProcess.pid, infoProcess.name, itSeg->second);
		}
	}

	/* Affichage des resultats */
	nbsResult = listChallenge.size() + listResponse.size();
	if (nbsResult > 0)
	{
		printModuleName(infoProcess);

		/* Recupere toutes les chaines de caracteres dans un set si besoin est */
		getEveryRWStrings(infoProcess);

		/* Pour tout les challenges et toutes les reponses */
		for (std::map<std::string, sInfoChallenge>::iterator itChallenge=listChallenge.begin();
		     itChallenge!=listChallenge.end(); )
		{
			ok = 0;

			for (std::map<std::string, sInfoResponse>::iterator itResponse=listResponse.begin();
			     itResponse!=listResponse.end(); )
			{
				/* Et pour toutes les chaines de caracteres */
				for (std::set<std::string>::iterator itStr=infoProcess.listRWStrings.begin();
				     itStr!=infoProcess.listRWStrings.end(); )
				{
					unsigned char	bufferHash[SIZE_NTLMSSP_HASH];
					unsigned char	bufferHashResponse[SIZE_NTLMSSP_HASH];

					/* On calcul la reponse que l'on aurait eu avec la chaine */
					NTMLv2Hash(bufferHash, itResponse->second.domainName.c_str(),
						itResponse->second.userName.c_str(), itStr->c_str());
					LMv2Response(bufferHashResponse, bufferHash, itResponse->second.info,
						itResponse->second.infoSize, itChallenge->second.challenge);

					/* Compare la reponse calculee avec celle recuperee en memoire */
					if (memcmp(bufferHashResponse, itResponse->second.ntlmHash, SIZE_NTLMSSP_HASH) == 0)
					{
						/* Affiche le pass */
						printf("    NTLMv2 password = \"" COLOR_RED "%s" COLOR_NC "\"\n",
							itStr->c_str());

						/* Affiche les infos du chall/reponse */
						printf("      Challenge %s (%s)\n", itChallenge->first.c_str(), itChallenge->second.targetName.c_str());
						printf("      Response :\n");
						printf("        Hash = \"%s\"\n", itResponse->first.c_str());
						printf("        Data = ");
						for (unsigned long i=0; i<itResponse->second.infoSize; i++)
							printf("%02x", (unsigned char)(itResponse->second.info[i]));
						printf("\n");
						printf("        Domain Name = \"%s\"\n", itResponse->second.domainName.c_str());
						printf("        User Name = \"%s\"\n", itResponse->second.userName.c_str());
						printf("        Host Name = \"%s\"\n", itResponse->second.hostName.c_str());

						/* Enleve le challenge et la reponse de la liste */
						ok = 1;
						listChallenge.erase(itChallenge++);
						listResponse.erase(itResponse);
						itResponse = listResponse.end();
						itStr = infoProcess.listRWStrings.end();
					}

					/* Passe au suivant si besoin est */
					if (ok == 0)
						itStr++;
				}

				/* Passe au suivant si besoin est */
				if (ok == 0)
					itResponse++;
			}

			/* Passe au suivant si besoin est */
			if (ok == 0)
				itChallenge++;
		}

		/* Affiche les challenge/reponses non resolu */
		if ((listChallenge.size() + listResponse.size()) > 0)
		{
			printModuleName(infoProcess);
			printf("    Unresolved challenge/response :\n");

			for (std::map<std::string, sInfoChallenge>::iterator itChallenge=listChallenge.begin();
			     itChallenge!=listChallenge.end();
			     itChallenge++)
			{
				printf("      Challenge %s (%s)\n", itChallenge->first.c_str(), itChallenge->second.targetName.c_str());
			}

			for (std::map<std::string, sInfoResponse>::iterator itResponse=listResponse.begin();
			     itResponse!=listResponse.end();
			     itResponse++)
			{
				printf("      Response :\n");

				printf("        Hash = \"%s\"\n", itResponse->first.c_str());
				printf("        Data = ");
				for (unsigned long i=0; i<itResponse->second.infoSize; i++)
					printf("%02x", (unsigned char)(itResponse->second.info[i]));
				printf("\n");
				printf("        Domain Name = \"%s\"\n", itResponse->second.domainName.c_str());
				printf("        User Name = \"%s\"\n", itResponse->second.userName.c_str());
				printf("        Host Name = \"%s\"\n", itResponse->second.hostName.c_str());
			}
		}
	}

	return (nbsResult);
}

/**
** \fn unsigned long searchNTLMSSPChallenge(std::map<std::string, sInfoChallenge> &dst,
**				std::map<unsigned long, sInfoMem*>::const_iterator &itSeg)
** \brief Gere l'extraction des infos des challenges NTLMv2 d'un segment
**
** \param dst Liste ou mettre les challenges (indexes par leur hash)
** \param itSeg Segment a analyser
** \return Retourne le nombre de challenges decouverts
*/
static unsigned long	searchNTLMSSPChallenge(std::map<std::string, sInfoChallenge> &dst,
						std::map<unsigned long, sInfoMem*>::const_iterator &itSeg)
{
	const char		*ptrContent;
	unsigned long		sizeContent;
	std::set<unsigned long>	listItem;
	sIdentifierNTLMSSP	magicNTLMSSPChallenge;
	sNTLMStringInfo		infoTargetName;
	std::string		serverName;
	uint32_t		negociateFlags;
	char			challenge[SIZE_NTLMSSP_CHALLENGE];
	char			strChallenge[64];
	unsigned long		offset;
	int			ok;

	//dst.clear();
	ptrContent = itSeg->second->content;
	sizeContent = itSeg->second->size;

	/* Prepare le magic-number identifiant les challenges NTLMSSP ("NTLMSSP\0" + NTLMSSP_CHALLENGE) */
	strncpy(magicNTLMSSPChallenge.magic, "NTLMSSP", 8);
	magicNTLMSSPChallenge.type = TYPE_NTLMSSP_CHALLENGE;

	/* Pour tout les patterns correspondant */
	searchData(listItem, ptrContent, sizeContent, 0, (const char*)&magicNTLMSSPChallenge, sizeof(magicNTLMSSPChallenge));
	for (std::set<unsigned long>::iterator itItem=listItem.begin();
	     itItem!=listItem.end();
	     itItem++)
	{
		if ((*itItem + sizeof(magicNTLMSSPChallenge) + sizeof(sNTLMStringInfo) + sizeof(uint32_t) + SIZE_NTLMSSP_CHALLENGE) < sizeContent)
		{
			ok = 1;
			offset = *itItem + sizeof(magicNTLMSSPChallenge);

			/* Recuperation des infos du nom du serveur */
			memset(challenge, 0, sizeof(challenge));
			memcpy(&infoTargetName, &(ptrContent[offset]), sizeof(sNTLMStringInfo));
			serverName.clear();
			if ((*itItem + infoTargetName.offset + infoTargetName.length) < sizeContent)
			{
				for (unsigned long i=0;
				    (i < infoTargetName.length) && ((*itItem + infoTargetName.offset + i) < sizeContent);
				    i++)
				{
					if (ptrContent[*itItem + infoTargetName.offset + i] != '\0')
						serverName += ptrContent[*itItem + infoTargetName.offset + i];
				}
			}
			else
				ok = 0;
			offset += sizeof(sNTLMStringInfo);

			if (ok == 1)
			{
				/* Recuperation des flags */
				memcpy(&(negociateFlags), &(ptrContent[offset]), sizeof(uint32_t));
				offset += sizeof(uint32_t);

				/* Recuperation du challenge */
				memcpy(challenge, &(ptrContent[offset]), SIZE_NTLMSSP_CHALLENGE);
				offset += sizeof(SIZE_NTLMSSP_CHALLENGE);

				/* Preparation de la string contenant le challenge */
				snprintf(strChallenge, 63, "%02x%02x%02x%02x%02x%02x%02x%02x",
					(unsigned char)challenge[0], (unsigned char)challenge[1],
					(unsigned char)challenge[2], (unsigned char)challenge[3],
					(unsigned char)challenge[4], (unsigned char)challenge[5],
					(unsigned char)challenge[6], (unsigned char)challenge[7]);

				/* Ajoute des infos du challenge NTLM a la liste */
				dst[strChallenge] = sInfoChallenge();
				dst[strChallenge].targetName = serverName;
				dst[strChallenge].negociateFlags = negociateFlags;
				memcpy(&(dst[strChallenge].challenge), challenge, SIZE_NTLMSSP_CHALLENGE);
			}
		}
	}

	return (dst.size());
}


/**
** \fn unsigned long searchNTLMSSPResponse(std::map<std::string, sInfoResponse> &dst,
**					std::map<unsigned long, sInfoMem*>::const_iterator &itSeg)
** \brief Gere l'extraction des infos des reponses aux challenges NTLMv2 d'un segment
**
** \param dst Liste ou mettre les reponses (indexees par leur hash)
** \param itSeg Segment a analyser
** \return Retourne le nombre de reponses decouvertes
*/
static unsigned long	searchNTLMSSPResponse(std::map<std::string, sInfoResponse> &dst,
					std::map<unsigned long, sInfoMem*>::const_iterator &itSeg)
{
	const char		*ptrContent;
	unsigned long		sizeContent;
	std::set<unsigned long>	listItem;
	sIdentifierNTLMSSP	magicNTLMSSPChallenge;
	sNTLMStringInfo		infoData;
	std::string		domainName;
	std::string		userName;
	std::string		hostName;
	char			hashNTLM[SIZE_NTLMSSP_HASH];
	char			strHashNTLM[64];
	char			data[SIZE_NTLMSSP_DATA_MAX];
	unsigned long		dataSize;
	unsigned long		offset;
	int			ok;

	//dst.clear();
	ptrContent = itSeg->second->content;
	sizeContent = itSeg->second->size;

	/* Prepare le magic-number identifiant les reponses NTLMSSP ("NTLMSSP\0" + NTLMSSP_AUTH) */
	strncpy(magicNTLMSSPChallenge.magic, "NTLMSSP", 8);
	magicNTLMSSPChallenge.type = TYPE_NTLMSSP_AUTH;

	/* Pour tout les patterns correspondant */
	searchData(listItem, ptrContent, sizeContent, 0, (const char*)&magicNTLMSSPChallenge, sizeof(magicNTLMSSPChallenge));
	for (std::set<unsigned long>::iterator itItem=listItem.begin();
	     itItem!=listItem.end();
	     itItem++)
	{
		if ((*itItem + sizeof(magicNTLMSSPChallenge) + (sizeof(sNTLMStringInfo) * 6)) < sizeContent)
		{
			ok = 1;
			offset = *itItem + sizeof(magicNTLMSSPChallenge);

			/* Infos Lan Manager Response */
			memset(hashNTLM, 0, sizeof(hashNTLM));
			memcpy(&infoData, &(ptrContent[offset]), sizeof(sNTLMStringInfo));
			offset += sizeof(sNTLMStringInfo);

			/* Infos NTLM Response */
			dataSize = 0;
			memcpy(&infoData, &(ptrContent[offset]), sizeof(sNTLMStringInfo));
			if ((*itItem + infoData.offset + infoData.length) < sizeContent)
			{
				/* Extraction du hash */
				memcpy(hashNTLM, &(ptrContent[*itItem + infoData.offset]), SIZE_NTLMSSP_HASH);

				/* Preparation de la string contenant le challenge */
				snprintf(strHashNTLM, 63, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
					(unsigned char)hashNTLM[0], (unsigned char)hashNTLM[1],
					(unsigned char)hashNTLM[2], (unsigned char)hashNTLM[3],
					(unsigned char)hashNTLM[4], (unsigned char)hashNTLM[5],
					(unsigned char)hashNTLM[6], (unsigned char)hashNTLM[7],
					(unsigned char)hashNTLM[8], (unsigned char)hashNTLM[9],
					(unsigned char)hashNTLM[10], (unsigned char)hashNTLM[11],
					(unsigned char)hashNTLM[12], (unsigned char)hashNTLM[13],
					(unsigned char)hashNTLM[14], (unsigned char)hashNTLM[15]);

				/* Extraction des donnees */
				if ((infoData.length > SIZE_NTLMSSP_HASH) && ((infoData.length - SIZE_NTLMSSP_HASH) < SIZE_NTLMSSP_DATA_MAX))
				{
					dataSize = infoData.length - SIZE_NTLMSSP_HASH;
					memcpy(data, &(ptrContent[*itItem + infoData.offset + SIZE_NTLMSSP_HASH]), dataSize);
				}
				else
					ok = 0;
			}
			else
				ok = 0;
			offset += sizeof(sNTLMStringInfo);

			/* Infos Domain Name */
			memcpy(&infoData, &(ptrContent[offset]), sizeof(sNTLMStringInfo));
			domainName.clear();
			if ((*itItem + infoData.offset + infoData.length) < sizeContent)
			{
				for (unsigned long i=0;
				    (i < infoData.length) && ((*itItem + infoData.offset + i) < sizeContent);
				    i++)
				{
					if (ptrContent[*itItem + infoData.offset + i] != '\0')
						domainName += ptrContent[*itItem + infoData.offset + i];
				}
			}
			else
				ok = 0;
			offset += sizeof(sNTLMStringInfo);

			/* Infos User Name */
			memcpy(&infoData, &(ptrContent[offset]), sizeof(sNTLMStringInfo));
			userName.clear();
			if ((*itItem + infoData.offset + infoData.length) < sizeContent)
			{
				for (unsigned long i=0;
				    (i < infoData.length) && ((*itItem + infoData.offset + i) < sizeContent);
				    i++)
				{
					if (ptrContent[*itItem + infoData.offset + i] != '\0')
						userName += ptrContent[*itItem + infoData.offset + i];
				}
			}
			else
				ok = 0;
			offset += sizeof(sNTLMStringInfo);

			/* Infos Host Name */
			memcpy(&infoData, &(ptrContent[offset]), sizeof(sNTLMStringInfo));
			hostName.clear();
			if ((*itItem + infoData.offset + infoData.length) < sizeContent)
			{
				for (unsigned long i=0;
				    (i < infoData.length) && ((*itItem + infoData.offset + i) < sizeContent);
				    i++)
				{
					if (ptrContent[*itItem + infoData.offset + i] != '\0')
						hostName += ptrContent[*itItem + infoData.offset + i];
				}
			}
			else
				ok = 0;
			offset += sizeof(sNTLMStringInfo);

			if (ok == 1)
			{
				/* Ajoute des infos de la reponse NTLM a la liste */
				dst[strHashNTLM] = sInfoResponse();
				memcpy(&(dst[strHashNTLM].ntlmHash), hashNTLM, SIZE_NTLMSSP_HASH);
				memcpy(&(dst[strHashNTLM].info), data, dataSize);
				dst[strHashNTLM].infoSize = dataSize;
				dst[strHashNTLM].domainName = domainName;
				dst[strHashNTLM].userName = userName;
				dst[strHashNTLM].hostName = hostName;
			}
		}
	}

	return (dst.size());
}

/**
** \fn void NTLMHashStr(unsigned char *dst, const char *str)
** \brief Calcul le hash NTLM d'une chaine de caracteres
**
** \param dst Buffer ou mettre le hash
** \param str Chaine a hasher (en ASCII et est converti en wide-char)
** \return Retourne rien
*/
static void	NTLMHashStr(unsigned char *dst, const char *str)
{
	char		buffer[512*2];
	char		*ptrBuffer;
	unsigned long	strSize;

	/* Pour les petites chaines, pas besoin d'allouer de buffer lors de la conversion ASCII -> Wide-char */
	if ((strSize = strlen(str)) < 512)
	{
		for (unsigned long i=0; i<strSize; i++)
		{
			buffer[i*2] = str[i];
			buffer[i*2+1] = '\0';
		}

		MD4_hash(dst, (const unsigned char*)buffer, strSize*2);
	}
	else
	{
		if ((ptrBuffer = new char[strSize*2]) != NULL)
		{
			for (unsigned long i=0; i<strSize; i++)
			{
				ptrBuffer[i*2] = str[i];
				ptrBuffer[i*2+1] = '\0';
			}

			MD4_hash(dst, (const unsigned char*)ptrBuffer, strSize*2);
			delete ptrBuffer;
		}
	}

}

/**
** \fn void NTMLv2Hash(unsigned char *dst, const char *target, const char *username, const char *password)
** \brief Calcul le hash NTLMv2 de l'utilisateur pour le domaine de la target
**
** \param dst Buffer ou mettre le hash
** \param target Nom de domaine de la target
** \param username Nom de l'utilisateur
** \param password Mot de passe de l'utilisateur
** \return Retourne rien
*/
static void	NTMLv2Hash(unsigned char *dst, const char *target, const char *username, const char *password)
{
	unsigned char	hashPass[SIZE_NTLMSSP_HASH];
	std::string	identity;
	unsigned long	sizeUsername;
	char		buffer[512*2];
	char		*ptrBuffer;
	unsigned long	strSize;

	NTLMHashStr(hashPass, password);

	sizeUsername = strlen(username);
	for (unsigned long i=0; i<sizeUsername; i++)
	{
		if (isupper(username[i]))
			identity += username[i];
		else
			identity += (username[i] - 0x20);
	}
	identity += target;

	/* Pour les petites chaines, pas besoin d'allouer de buffer lors de la conversion ASCII -> Wide-char */
	if ((strSize = strlen(identity.c_str())) < 512)
	{
		for (unsigned long i=0; i<strSize; i++)
		{
			buffer[i*2] = identity.c_str()[i];
			buffer[i*2+1] = '\0';
		}

		hmac_md5(hashPass, (const unsigned char*)buffer, strSize*2, dst);
	}
	else
	{
		if ((ptrBuffer = new char[strSize*2]) != NULL)
		{
			for (unsigned long i=0; i<strSize; i++)
			{
				ptrBuffer[i*2] = identity.c_str()[i];
				ptrBuffer[i*2+1] = '\0';
			}

			hmac_md5(hashPass, (const unsigned char*)ptrBuffer, strSize*2, dst);
			delete ptrBuffer;
		}
	}
}

/**
** \fn void LMv2Response(unsigned char *dst, const unsigned char *hash,
**			const unsigned char *blob, unsigned long blobSize,
**			const unsigned char *challenge)
** \brief Calcul le hash d'une reponse NTLMv2 a partir d'un challenge, blob, pass...
**
** \param dst Buffer ou mettre le hash
** \param hash Hash NTLMv2
** \param blob Blob contenant les infos du serveur
** \param blobSize Taille du blob
** \param challenge Hash recu dans le challenge
** \return Retourne rien
*/
static void	LMv2Response(unsigned char *dst, const unsigned char *hash,
				const unsigned char *blob, unsigned long blobSize,
				const unsigned char *challenge)
{
	unsigned char	buffer[2048];

	memcpy(buffer, challenge, 8);
	memcpy(&(buffer[8]), blob, blobSize);
	hmac_md5(hash, buffer, blobSize+8, dst);
}

