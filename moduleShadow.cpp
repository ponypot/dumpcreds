#include	"header.h"


/**
** \struct sInfoHash
** \param Structure contenant les infos des hashs
*/
struct	sInfoHash
{
	/** Hash */
	std::string	hash;
	/** Mot de passe corespondant au hash (si on le trouvre, "" sinon) */
	std::string	password;
	/** Nom de l'utilisateur (si on le connait ("" sinon) */
	std::string	username;
};

static unsigned long	searchShadowHash(std::map<std::string, sInfoHash> &dst,
					std::map<unsigned long, sInfoMem*>::const_iterator &itSeg);
static unsigned long	getHashFromEtcShadow(std::map<std::string, sInfoHash> &dst);
static unsigned long	searchHashString(sInfoProcess &infoProcess, std::map<std::string, sInfoHash> &hash);
static void		printHashInfo(std::map<std::string, sInfoHash>::iterator &info, sInfoProcess &infoProcess);


/**
** \fn unsigned long moduleShadowExec(sInfoProcess &infoProcess, const sUserParam &param)
** \brief Extrait les hashs de type "$x$salt$hash" et cherche le pass correspondant dans les segments RW
** 
** \param infoProcess Structure contenant les infos du processus a analyser
** \param param Structure contenant les options utilisateurs
** \return Retourne le nombre de hashs trouves
*/
unsigned long	moduleShadowExec(sInfoProcess &infoProcess, const sUserParam &param)
{
	unsigned long				nbsResult;
	unsigned long				findResultInSegment;
	std::map<std::string, sInfoHash>	listHash;

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
			/* Cherche les hashs dans le segment */
			findResultInSegment = searchShadowHash(listHash, itSeg);
			nbsResult += findResultInSegment;
		}

		/* Cree le fichier de dump si besoin est */
		if ((findResultInSegment > 0) && (param.dump != 0))
		{
			saveSegmentToFile(infoProcess.pid, infoProcess.name, itSeg->second);
		}
	}

	/* Si on a trouve des hashs */
	if (listHash.size() > 0)
	{
		/* On tente de trouver le pass correspondant */
		searchHashString(infoProcess, listHash);
	}

	return (nbsResult);
}

/**
** \fn unsigned long moduleEtcShadowExec(sInfoProcess &infoProcess, const sUserParam &param)
** \brief Extrait les hashs de "/etc/shadow" et cherche les pass correspondants dans les segments RW
** 
** \param infoProcess Structure contenant les infos du processus a analyser
** \param param Structure contenant les options utilisateurs
** \return Retourne le nombre de hashs trouves
*/
unsigned long	moduleEtcShadowExec(sInfoProcess &infoProcess, const sUserParam &param)
{
	std::map<std::string, sInfoHash>	listHash;
	unsigned long				nbsResult;

	/* Si le mode "--force" n'est pas actif, on ne traite que certains processus */
	if ( (param.force == 0) &&
	     (strcasestr(infoProcess.name.c_str(), "gdm-session-worker") == NULL) &&
	     (strcasestr(infoProcess.name.c_str(), "gnome-keyring") == NULL) &&
	     (strcasestr(infoProcess.name.c_str(), "gnome-shell") == NULL) &&
	     (strcasestr(infoProcess.name.c_str(), "lightdm") == NULL) )
		return (0);

	/* Si on peut recuperer des hashs dans "/etc/shadow" */
	nbsResult = 0;
	if (getHashFromEtcShadow(listHash) > 0)
	{
		/* On tente de trouver le pass correspondant */
		nbsResult = searchHashString(infoProcess, listHash);
	}

	return (nbsResult);
}

/**
** \fn unsigned long searchShadowHash(std::map<std::string, sInfoHash> &dst,
**				std::map<unsigned long, sInfoMem*>::const_iterator &itSeg)
** \brief Gere l'identification des hash au format '/etc/shadow' situe en memoire
**
** \param dst Liste ou mettre les hashs trouves
** \param itSeg Information du segment en cours d'analyse
** \return Retourne le nombre de hash trouves
*/
static unsigned long	searchShadowHash(std::map<std::string, sInfoHash> &dst,
					std::map<unsigned long, sInfoMem*>::const_iterator &itSeg)
{
	unsigned long	nbsHashInSeg;
	const char	*tabIdentHash[] =
	{
		"$1$", "$2a$", "$5$", "$6$", NULL
	};
	unsigned long	tabSizeHash[] =
	{
		22,    0,      43,    86,    0
	};
	std::set<unsigned long>	listItem;
	const char		*ptrContent;
	unsigned long		sizeContent;
	unsigned long		patternSize;
	unsigned long		sizeSalt;
	unsigned long		sizeHash;
	int			ok;
	sInfoHash		infoHashTmp;

	//dst.clear();
	nbsHashInSeg = 0;
	ptrContent = itSeg->second->content;
	sizeContent = itSeg->second->size;

	/* Pour tout les types de hash */
	for (unsigned long indexTypeHash=0; tabIdentHash[indexTypeHash]!=NULL; indexTypeHash++)
	{
		patternSize = strlen(tabIdentHash[indexTypeHash]);
		searchString(listItem, ptrContent, sizeContent, 0, tabIdentHash[indexTypeHash]);

		/* Pour tout les patterns correspondant */
		for (std::set<unsigned long>::iterator itItem=listItem.begin();
		     itItem!=listItem.end();
		     itItem++)
		{
			ok = 1;

			/* Passe le salt */
			sizeSalt = 0;
			while (myIsShadowChar(ptrContent[*itItem+patternSize+sizeSalt]))
				sizeSalt++;
			if ((sizeSalt < 1) ||
			    (ptrContent[*itItem+patternSize+sizeSalt] != '$'))
				ok = 0;
			else
				sizeSalt++;

			if (ok == 1)
			{
				/* Passe le hash */
				sizeHash = 0;
				while (myIsShadowChar(ptrContent[*itItem+patternSize+sizeSalt+sizeHash]))
					sizeHash++;
				if ((tabSizeHash[indexTypeHash] > 0) && (sizeHash != tabSizeHash[indexTypeHash]))
					ok = 0;

				/* Si on a trouve un hash, on l'ajoute a la liste */
				if ((ok == 1) && ((patternSize + sizeSalt + sizeHash) < 1023))
				{
					infoHashTmp.hash = std::string(&(ptrContent[*itItem]), (patternSize + sizeSalt + sizeHash));
					infoHashTmp.password = "";
					infoHashTmp.username = "";

					dst[infoHashTmp.hash] = infoHashTmp;
					nbsHashInSeg++;
				}
			}
		}
	}

	return (nbsHashInSeg);
}

/**
** \fn unsigned long getHashFromEtcShadow(std::map<std::string, sInfoHash> &dst)
** \brief Recupere les hashs presents dans "/etc/shadow"
**
** \param dst Liste ou mettre les infos des hashs
** \return Retourne le nombre de hashs recuperes
*/
static unsigned long	getHashFromEtcShadow(std::map<std::string, sInfoHash> &dst)
{
	std::ifstream	file("/etc/shadow");
	std::string	line;
	std::string	nameTmp;
	std::string	hashTmp;
	unsigned long	offsetTmp;
	unsigned long	offsetTmp2;
	sInfoHash	infoHashTmp;

	dst.clear();
	
	if (file)
	{
		while (std::getline(file, line))
		{
			/* Recupere le username */
			if ((offsetTmp = line.find(":")) != std::string::npos)
			{
				nameTmp = line.substr(0, offsetTmp);
				offsetTmp++;
				
				/* Recupere le hash */
				if ((offsetTmp2 = line.find(":", offsetTmp)) != std::string::npos)
				{
					hashTmp = line.substr(offsetTmp, offsetTmp2-offsetTmp);
					
					/* Si le hash a un magic correct, on l'insere dans la liste */
					if ( (dst.find(hashTmp) == dst.end()) &&
					     ((hashTmp.find("$1$") == 0) ||
					      (hashTmp.find("$2a$") == 0) ||
					      (hashTmp.find("$5$") == 0) ||
					      (hashTmp.find("$6$") == 0)) )
					{
						infoHashTmp.hash = hashTmp;
						infoHashTmp.password = "";
						infoHashTmp.username = nameTmp;
						dst[hashTmp] = infoHashTmp;
					}
				}
			}
		}
	}

	return (dst.size());
}

/**
** \fn unsigned long searchHashString(sInfoProcess &infoProcess, std::map<std::string, sInfoHash> &hash)
** \brief Cherche les chaines de caracteres ayant servies a generer les hashs
**
** \param infoProcess Structure contenant les infos du processus a analyser
** \param hash Liste des hashs
** \return Retourne le nombre de nombre de correspondances hash/pass trouvees
*/
static unsigned long	searchHashString(sInfoProcess &infoProcess, std::map<std::string, sInfoHash> &hash)
{
	unsigned long	nbsResult;
	char		bufferSalt[1024];
	unsigned long	nbsDollars;
	char		*hashTmp;
	int		ok;

	nbsResult = 0;

	/* On recupere toutes les chaines de caracteres des segments RW */
	getEveryRWStrings(infoProcess);

	/* Pour tout les hashs */
	for (std::map<std::string, sInfoHash>::iterator itHash=hash.begin();
	     itHash!=hash.end(); )
	{
		ok = 0;

		/* Prepare le salt devant servir a hasher les chaines */
		nbsDollars = 0;
		for (unsigned long i=0; (itHash->first.c_str()[i]!='\0') && (nbsDollars<3); i++)
		{
			bufferSalt[i] = itHash->first.c_str()[i];
			bufferSalt[i+1] = '\0';

			if (bufferSalt[i] == '$')
				nbsDollars++;
		}

		/* Pour toutes les chaines du set */
		for (std::set<std::string>::iterator itStr=infoProcess.listRWStrings.begin();
		     itStr!=infoProcess.listRWStrings.end(); )
		{
			/* Hash la chaine */
			hashTmp = crypt(itStr->c_str(), bufferSalt);

			/* Si le hash calcule correspond a celui de la liste */
			if (itHash->first == hashTmp)
			{
				/* Si on a trouve le pass, on l'affiche */
				itHash->second.password = (*itStr);
				printHashInfo(itHash, infoProcess);

				ok = 1;
				itHash = hash.erase(itHash++);
				itStr = infoProcess.listRWStrings.end();
				nbsResult++;
			}
			else
				itStr++;
		}
		
		/* Passe au hase suivant si besoin est */
		if (ok == 0)
			itHash++;
	}

	/* Affiche les hashs sans correspondances */
	for (std::map<std::string, sInfoHash>::iterator itHash=hash.begin();
	     itHash!=hash.end();
	     itHash++)
	{
		printHashInfo(itHash, infoProcess);
	}

	return (nbsResult);
}

/**
** \fn void printHashInfo(std::map<std::string, sInfoHash>::iterator &info, sInfoProcess &infoProcess)
** \brief Gere l'affichage des infos d'un hash
**
** \param info Hash a afficher
** \param infoProcess Structure contenant les infos du processus a analyser
** \return Retourne rien
*/
static void	printHashInfo(std::map<std::string, sInfoHash>::iterator &info, sInfoProcess &infoProcess)
{
	/*
	** S'il y a un nom mais pas de pass, c'est que le hash viens de "/etc/shadow" :
	** On ne l'affiche que si on a trouve le password
	*/
	if ((info->second.username.size() <= 0) || (info->second.password.size() > 0))
	{
		printModuleName(infoProcess);
		printf("    Hash: " COLOR_RED "%s" COLOR_NC, info->second.hash.c_str());
		
		if (info->second.password.size() > 0)
			printf(" = \"" COLOR_RED "%s" COLOR_NC "\"", info->second.password.c_str());
		if (info->second.username.size() > 0)
			printf(" (%s)", info->second.username.c_str());
			
		printf("\n");
	}
}

