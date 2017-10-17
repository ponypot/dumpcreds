#include	"header.h"



/**
** \fn unsigned long moduleStringsExec(sInfoProcess &infoProcess, const sUserParam &param)
** \brief Extrait les chaines de caracteres des segments
** 
** \param infoProcess Structure contenant les infos du processus a analyser
** \param param Structure contenant les options utilisateurs
** \return Retourne toujours 0
*/
unsigned long	moduleStringsExec(sInfoProcess &infoProcess, const sUserParam &/*param*/)
{
	const char	*ptrContent;
	unsigned long	sizeContent;
	unsigned long	addrContent;
	unsigned long	nbsChar;

	/* Pour tout les segments */
	for (std::map<unsigned long, sInfoMem*>::const_iterator itSeg=infoProcess.listSeg.begin();
	     itSeg!=infoProcess.listSeg.end();
	     itSeg++)
	{
		if (itSeg->second->size > SIZE_STRING_MIN)
		{
			ptrContent = itSeg->second->content;
			sizeContent = itSeg->second->size;
			addrContent = itSeg->second->addr;

			for (unsigned long offset=0; offset<sizeContent-SIZE_STRING_MIN; offset++)
			{
				/* Filtre les caracteres superieurs a 0x80 et inferieur a 0x20 pour gagner du temps */
				if ( ( (*((uint32_t*)&(ptrContent[offset])) & 0x80000000) != 0) ||
				     ( (*((uint32_t*)&(ptrContent[offset])) & 0xe0000000) == 0) )
					offset += sizeof(uint32_t);
				else
				{
					nbsChar = countPrintableChar(ptrContent, sizeContent, offset);
					if (nbsChar > SIZE_STRING_MIN)
					{
						printModuleName(infoProcess);
						printf("    %lx: %.*s\n", addrContent+offset, (int)nbsChar, &(ptrContent[offset]));
						offset += nbsChar;
					}
				}
			}
		}
	}

	return (0);
}

