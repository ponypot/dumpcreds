#include	"header.h"



/**
** \fn unsigned long moduleParamHttpExec(sInfoProcess &infoProcess, const sUserParam &param)
** \brief Extrait les patterns "password", "pass"... des segments RW
** 
** \param infoProcess Structure contenant les infos du processus a analyser
** \param param Structure contenant les options utilisateurs
** \return Retourne le nombre de parametres trouves
*/
unsigned long	moduleParamHttpExec(sInfoProcess &infoProcess, const sUserParam &param)
{
	const char		*ptrContent;
	unsigned long		sizeContent;
	unsigned long		addrContent;
	unsigned long		patternSize;
	std::set<unsigned long>	listItem;
	int			ok;
	unsigned long		nbsCharBefore;
	unsigned long		nbsCharPass;
	unsigned long		nbsCharAfter;
	unsigned long		nbsResult;
	unsigned long		findResultInSegment;
	std::set<std::string>	listParamNames;

	/* Liste des noms de parametres a chercher */
	listParamNames.insert("password");
	listParamNames.insert("passwd");
	listParamNames.insert("pass");
	listParamNames.insert("pwd");

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
			ptrContent = itSeg->second->content;
			sizeContent = itSeg->second->size;
			addrContent = itSeg->second->addr;

			/* Cherche tous les "=" */
			searchString(listItem, ptrContent, sizeContent, 0, "=");
			for (std::set<unsigned long>::iterator itItem=listItem.begin();
			     itItem!=listItem.end();
			     itItem++)
			{
				/* On cherche toutes les chaines pouvant correspondre a des credentials HTTP */
				for (std::set<std::string>::const_iterator itPattern=listParamNames.begin();
				     itPattern!=listParamNames.end();
				     itPattern++)
				{
					ok = 1;

					patternSize = strlen(itPattern->c_str());
					if ((*itItem <= patternSize) ||
					    (strncasecmp(&(ptrContent[*itItem-patternSize]), itPattern->c_str(), patternSize) != 0))
						ok = 0;

					if (ok != 0)
					{
						/* Il faut '?', '&', '\r', '\n' ou un caractere non affichable avant le pattern */
						if ((*itItem > 0) &&
						    (isprint(ptrContent[*itItem-patternSize-1]) != 0) &&
						    (ptrContent[*itItem-patternSize-1] != '?') &&
						    (ptrContent[*itItem-patternSize-1] != '&') &&
						    (ptrContent[*itItem-patternSize-1] != '\r') &&
						    (ptrContent[*itItem-patternSize-1] != '\n'))
							ok = 0;

						if (ok != 0)
						{
							/* Cherche les caracteres du credential */
							nbsCharPass = 1;	/* ptrContent[*itItem] == '=' */
							while (myParamHTTPChar(ptrContent[*itItem+nbsCharPass]))
								nbsCharPass++;
							if (nbsCharPass < 4)
								ok = 0;

							if (ok == 1)
							{
								/* Cherche ou commence la chaine de caractere */
								nbsCharBefore = 0;
								while ( (*itItem-patternSize > nbsCharBefore+1) &&
								        (isgraph(ptrContent[*itItem-patternSize-nbsCharBefore-1])) )
									nbsCharBefore++;

								/* Cherche les caracteres de la fin de la requete */
								nbsCharAfter = 0;
								while (isgraph(ptrContent[*itItem+nbsCharPass+nbsCharAfter]))
									nbsCharAfter++;

								printModuleName(infoProcess);
								printf("    %lx: %.*s",
									*itItem+addrContent-patternSize,
									(int)nbsCharBefore, &(ptrContent[*itItem-patternSize-nbsCharBefore]));
								printf(COLOR_RED "%.*s" COLOR_NC,
									(int)(patternSize + nbsCharPass), &(ptrContent[*itItem-patternSize]));
								printf("%.*s\n",
									(int)nbsCharAfter, &(ptrContent[*itItem+nbsCharPass]));
								nbsResult++;
								findResultInSegment++;
							}
						}
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

