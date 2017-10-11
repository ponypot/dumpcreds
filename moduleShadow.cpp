#include	"header.h"



static unsigned long	searchShadowHash(std::set<std::string> &dst,
					std::map<unsigned long, sInfoMem*>::const_iterator &itSeg);
static unsigned long	searchHashString(sInfoProcess &infoProcess, std::set<std::string> &hash);



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
	std::set<std::string>			listHash;

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
** \fn unsigned long searchShadowHash(std::set<std::string> &dst,
**				std::map<unsigned long, sInfoMem*>::const_iterator &itSeg)
** \brief Gere l'identification des hash au format '/etc/shadow' situe en memoire
**
** \param dst Liste ou mettre les hashs trouves
** \param itSeg Information du segment en cours d'analyse
** \return Retourne le nombre de hash trouves
*/
static unsigned long	searchShadowHash(std::set<std::string> &dst,
					std::map<unsigned long, sInfoMem*>::const_iterator &itSeg)
{
	unsigned long	nbsHashInSeg;
	const char	*tabIdentHash[] =
	{
		"$1$", "$2a$", "$5$", "$6$", NULL
	};
	std::set<unsigned long>	listItem;
	const char		*ptrContent;
	unsigned long		sizeContent;
	unsigned long		patternSize;
	unsigned long		sizeSalt;
	unsigned long		sizeHash;
	int			ok;
	char			bufferHashTmp[1024];

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
				if (sizeHash < 5)
					ok = 0;

				/* Si on a trouve un hash, on l'ajoute a la liste */
				if ((ok == 1) && ((patternSize + sizeSalt + sizeHash) < 1023))
				{
					memcpy(bufferHashTmp, &(ptrContent[*itItem]), (patternSize + sizeSalt + sizeHash));
					bufferHashTmp[patternSize + sizeSalt + sizeHash] = '\0';

					dst.insert(bufferHashTmp);
					nbsHashInSeg++;
				}
			}
		}
	}

	return (nbsHashInSeg);
}

/**
** \fn unsigned long searchHashString(sInfoProcess &infoProcess, std::set<std::string> &hash)
** \brief Cherche les chaines de caracteres ayant servies a generer les hashs
**
** \param infoProcess Structure contenant les infos du processus a analyser
** \param hash Liste des hashs
** \return Retourne le nombre de nombre de correspondance hash/pass trouvee
*/
static unsigned long	searchHashString(sInfoProcess &infoProcess, std::set<std::string> &hash)
{
	std::map<std::string, std::string>	mapHashAndPass;
	char					bufferSalt[1024];
	unsigned long				nbsDollars;
	char					*hashTmp;
	int					printedResult;

	printedResult = 0;

	/* Prepare la map de resultat */
	for (std::set<std::string>::const_iterator itHash=hash.begin();
	     itHash!=hash.end();
	     itHash++)
	{
		mapHashAndPass[*itHash] = "";
	}

	/* On recupere toutes les chaines de caracteres des segments RW */
	getEveryRWStrings(infoProcess);

	/* Pour tout les hashs */
	for (std::set<std::string>::iterator itHash=hash.begin();
	     itHash!=hash.end();
	     itHash++)
	{
		/* Prepare le salt devant servir a hasher les chaines */
		nbsDollars = 0;
		for (unsigned long i=0; ((*itHash)[i]!='\0') && (nbsDollars<3); i++)
		{
			bufferSalt[i] = (*itHash)[i];
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
			if (*itHash == hashTmp)
			{
				if (printedResult == 0)
				{
					printf("  Hash shadow:\n");
					printedResult = 1;
				}

				/* Si on a trouve le pass, on l'ajoute a la liste et on l'affiche */
				mapHashAndPass[hashTmp] = (*itStr);

				printf("    Hash: " 
					COLOR_RED "%s" COLOR_NC 
					" = \"" 
					COLOR_RED "%s" COLOR_NC "\"\n",
					itHash->c_str(), itStr->c_str());

				itStr = infoProcess.listRWStrings.end();
			}
			else
				itStr++;
		}
	}

	/* Affiche les hashs sans correspondances */
	for (std::map<std::string, std::string>::const_iterator itHash=mapHashAndPass.begin();
	     itHash!=mapHashAndPass.end();
	     itHash++)
	{
		if (itHash->second.size() <= 0)
		{
			if (printedResult == 0)
			{
				printf("  Hash shadow:\n");
				printedResult = 1;
			}

			printf("    Hash: " COLOR_RED "%s" COLOR_NC "\n", itHash->first.c_str());
		}
	}

	return (mapHashAndPass.size());
}

