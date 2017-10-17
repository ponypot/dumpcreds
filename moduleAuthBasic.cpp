#include	"header.h"

#define	PATTERN_AUTH_BASIC	"Authorization: Basic"



/**
** \fn unsigned long moduleAuthBasicExec(sInfoProcess &infoProcess, const sUserParam &param)
** \brief Extrait les patterns "Authorization: Basic *" des segments RW
** 
** \param infoProcess Structure contenant les infos du processus a analyser
** \param param Structure contenant les options utilisateurs
** \return Retourne le nombre de patterns trouves
*/
unsigned long	moduleAuthBasicExec(sInfoProcess &infoProcess, const sUserParam &param)
{
	const char		*ptrContent;
	unsigned long		sizeContent;
	unsigned long		addrContent;
	std::set<unsigned long>	listItem;
	int			ok;
	unsigned long		sizePattern;
	unsigned long		nbsSpace;
	unsigned long		nbsCharPass;
	unsigned long		nbsResult;
	unsigned long		findResultInSegment;

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
			/* Cherche les patterns correspondants */
			ptrContent = itSeg->second->content;
			sizeContent = itSeg->second->size;
			addrContent = itSeg->second->addr;
			sizePattern = strlen(PATTERN_AUTH_BASIC);
			searchString(listItem, ptrContent, sizeContent, 0, PATTERN_AUTH_BASIC);
			
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
					while ((ptrContent[*itItem+sizePattern+nbsSpace] == ' ') ||
					       (ptrContent[*itItem+sizePattern+nbsSpace] == '\t'))
					while (isspace(ptrContent[*itItem+sizePattern+nbsSpace]))
						nbsSpace++;
					if (nbsSpace <= 0)
						ok = 0;
					
					/* Passe les caracteres du pass encode en base64 */
					nbsCharPass = 0;
					while (isalnum(ptrContent[*itItem+sizePattern+nbsSpace+nbsCharPass]) ||
					        (ptrContent[*itItem+sizePattern+nbsSpace+nbsCharPass] == '+') ||
					        (ptrContent[*itItem+sizePattern+nbsSpace+nbsCharPass] == '/') ||
					        (ptrContent[*itItem+sizePattern+nbsSpace+nbsCharPass] == '='))
						nbsCharPass++;
					if (nbsCharPass <= 0)
						ok = 0;
					
					/* Affiche le pass si le pattern semble valide */
					if (ok == 1)
					{
						printModuleName(infoProcess);

						printf("    %lx: %.*s", *itItem+addrContent,
							(int)(sizePattern+nbsSpace), &(ptrContent[*itItem]));
						printf(COLOR_RED "%.*s\n" COLOR_NC,
							(int)nbsCharPass, &(ptrContent[*itItem+sizePattern+nbsSpace]));
						nbsResult++;
						findResultInSegment++;
					}
				}	
					
			}
		}

		/* Cree le fichier de dump si besoin est */
		if ((findResultInSegment > 0) && (param.dump != 0))
		{
			saveSegmentToFile(infoProcess.pid, infoProcess.name, itSeg->second);
		}
	}

	return (nbsResult);
}

