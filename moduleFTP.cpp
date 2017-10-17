#include	"header.h"

#define	PATTERN_USER		"user"
#define	PATTERN_USER_SIZE_MIN	4
#define	PATTERN_PASS		"pass"
#define	PATTERN_PASS_SIZE_MIN	4



static unsigned long	searchFTPCredentials(std::map<unsigned long, sInfoMem*>::const_iterator &itSeg,
					const char *pattern, unsigned long sizeCredsMin,
					sInfoProcess &infoProcess);
					
					

/**
** \fn unsigned long moduleFTPExec(sInfoProcess &infoProcess, const sUserParam &param)
** \brief Extrait les patterns "user *" et "pass *" des segments RW
** 
** \param infoProcess Structure contenant les infos du processus a analyser
** \param param Structure contenant les options utilisateurs
** \return Retourne toujours 0
*/
unsigned long	moduleFTPExec(sInfoProcess &infoProcess, const sUserParam &param)
{
	unsigned long	nbsResult;
	unsigned long	findResultInSegment;

	/* Si le mode "--force" n'est pas actif, on ne traite que les processus ayant "ftp" dans le nom */
	if ( (param.force == 0) && (strcasestr(infoProcess.name.c_str(), "ftp") == NULL) )
		return (0);

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
			/* Cherche les patterns d'authentification FTP */
			findResultInSegment += searchFTPCredentials(itSeg, PATTERN_USER, PATTERN_USER_SIZE_MIN, infoProcess);
			nbsResult += findResultInSegment;
			findResultInSegment += searchFTPCredentials(itSeg, PATTERN_PASS, PATTERN_PASS_SIZE_MIN, infoProcess);
			nbsResult += findResultInSegment;
		}

		/* Cree le fichier de dump si besoin est */
		if ((findResultInSegment > 0) && (param.dump != 0))
		{
			saveSegmentToFile(infoProcess.pid, infoProcess.name, itSeg->second);
		}
	}

	return (nbsResult);
}

/**
** \fn unsigned long searchFTPCredentials(std::map<unsigned long, sInfoMem*>::const_iterator &itSeg,
**					const char *pattern, unsigned long sizeCredsMin,
**					sInfoProcess &infoProcess)
** \brief Gere la recherche de credentials FTP dans un segment grace à un pattern
**
** \param itSeg Segment a analyser
** \param pattern Pattern permettant d'identifer un credential FTP
** \param sizeCredsMin Taille minimum des identifiants a recuperer
** \param printedResult un resultat a il deja ete affiche ?
** \return Retourne le nombre de patterns decouverts
*/
static unsigned long	searchFTPCredentials(std::map<unsigned long, sInfoMem*>::const_iterator &itSeg,
					const char *pattern, unsigned long sizeCredsMin,
					sInfoProcess &infoProcess)
{
	const char		*ptrContent;
	unsigned long		sizeContent;
	unsigned long		addrContent;
	unsigned long		patternSize;
	std::set<unsigned long>	listItem;
	int			ok;
	unsigned long		nbsSpace;
	unsigned long		nbsCharPass;
	unsigned long		nbsResult;

	/* Cherche les patterns correspondants */
	nbsResult = 0;
	ptrContent = itSeg->second->content;
	sizeContent = itSeg->second->size;
	addrContent = itSeg->second->addr;
	patternSize = strlen(pattern);
	searchStringI(listItem, ptrContent, sizeContent, 0, pattern);
			
	for (std::set<unsigned long>::iterator itItem=listItem.begin();
	     itItem!=listItem.end();
	     itItem++)
	{
		ok = 1;
		if ( (*itItem > 0) && 
		     ((isalnum(ptrContent[*itItem-1])) || (ptrContent[*itItem-1] == '_')) )
			ok = 0;
		else
		{
			/* Passe les espaces avant le pass */
			nbsSpace = 0;
			while ((ptrContent[*itItem+patternSize+nbsSpace] == ' ') ||
			       (ptrContent[*itItem+patternSize+nbsSpace] == '\t'))
				nbsSpace++;
			if (nbsSpace <= 0)
				ok = 0;
					
			/* Passe les caracteres du pass */
			nbsCharPass = 0;
			while (isgraph(ptrContent[*itItem+patternSize+nbsSpace+nbsCharPass]))
				nbsCharPass++;
			if (nbsCharPass <= sizeCredsMin)
				ok = 0;
					
			/* On doit etre en fin de ligne */
			if ((ptrContent[*itItem+patternSize+nbsSpace+nbsCharPass] != ' ') &&
			    (ptrContent[*itItem+patternSize+nbsSpace+nbsCharPass] != '\t') &&
			    (ptrContent[*itItem+patternSize+nbsSpace+nbsCharPass] != '\r') &&
			    (ptrContent[*itItem+patternSize+nbsSpace+nbsCharPass] != '\n') &&
			    (ptrContent[*itItem+patternSize+nbsSpace+nbsCharPass] != '\0'))
				ok = 0;
					
			/* Affiche le pass si le pattern semble valide */
			if (ok == 1)
			{
				printModuleName(infoProcess);
				printf("    %lx: %.*s", *itItem+addrContent,
					(int)(patternSize+nbsSpace), &(ptrContent[*itItem]));
				printf(COLOR_RED "%.*s\n" COLOR_NC,
					(int)nbsCharPass, &(ptrContent[*itItem+patternSize+nbsSpace]));
				nbsResult++;
			}
		}		
	}
	
	return (nbsResult);
}

