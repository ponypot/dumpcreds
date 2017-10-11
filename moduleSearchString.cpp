#include	"header.h"



static char	charOrDot(char c);
static void	hexDumpData(const char *buffer, unsigned long bufferSize, unsigned long bufferAddr,
				unsigned long addrDump, unsigned long sizeDump);
static void	funcShowWhoUseIt(const std::map<unsigned long, sInfoMem*> &listSeg,
				const std::map<unsigned long, sInfoMem*>::const_iterator &itSeg,
				unsigned long offsetPattern);



/**
** \fn unsigned long moduleSearchStringExec(sInfoProcess &infoProcess, const sUserParam &param)
** \brief Extrait les patterns definis par l'utilisateur dans tout les segments
** 
** \param infoProcess Structure contenant les infos du processus a analyser
** \param param Structure contenant les options utilisateurs
** \return Retourne le nombre d'occurences trouvees dans les segments
*/
unsigned long	moduleSearchStringExec(sInfoProcess &infoProcess, const sUserParam &param)
{
	const char		*ptrContent;
	unsigned long		sizeContent;
	unsigned long		addrContent;
	unsigned long		patternSize;
	std::set<unsigned long>	listItem;
	unsigned long		nbsCharBefore;
	unsigned long		nbsCharAfter;
	unsigned long		nbsResult;
	unsigned long		findResultInSegment;
	int			printedResult;

	printedResult = 0;

	/* Pour tout les segments */
	nbsResult = 0;
	for (std::map<unsigned long, sInfoMem*>::const_iterator itSeg=infoProcess.listSeg.begin();
	     itSeg!=infoProcess.listSeg.end();
	     itSeg++)
	{
		findResultInSegment = 0;
		ptrContent = itSeg->second->content;
		sizeContent = itSeg->second->size;
		addrContent = itSeg->second->addr;

		/* On cherche tout les patterns specifies par l'utilisateur */
		for (std::set<std::string>::const_iterator itPattern=param.listPatterns.begin();
		     itPattern!=param.listPatterns.end();
		     itPattern++)
		{
			/* Cherche les patterns correspondants */
			patternSize = strlen(itPattern->c_str());
			searchString(listItem, ptrContent, sizeContent, 0, itPattern->c_str());

			for (std::set<unsigned long>::iterator itItem=listItem.begin();
			     itItem!=listItem.end();
			     itItem++)
			{
				/* Cherche ou commence la chaine de caractere */
				nbsCharBefore = 0;
				while ( (*itItem > nbsCharBefore+1) &&
				        ((isgraph(ptrContent[*itItem-nbsCharBefore-1])) || 
				         (ptrContent[*itItem-nbsCharBefore-1] == ' ') || 
				         (ptrContent[*itItem-nbsCharBefore-1] == '\t')) )
					nbsCharBefore++;

				/* Cherche ou fini la chaine de caractere */
				nbsCharAfter = 0;
				while ((isgraph(ptrContent[*itItem+patternSize+nbsCharAfter])) || 
				         (ptrContent[*itItem+patternSize+nbsCharAfter] == ' ') || 
				         (ptrContent[*itItem+patternSize+nbsCharAfter] == '\t'))
					nbsCharAfter++;

				if (printedResult == 0)
				{
					printf("  Strings:\n");
					printedResult = 1;
				}

				printf("    %lx: %.*s", *itItem+addrContent, (int)nbsCharBefore, &(ptrContent[*itItem-nbsCharBefore]));
				printf(COLOR_RED "%.*s" COLOR_NC, (int)patternSize, &(ptrContent[*itItem]));
				printf("%.*s\n", (int)nbsCharAfter, &(ptrContent[*itItem+strlen(itPattern->c_str())]));
				nbsResult++;
				findResultInSegment++;

				/* En mode verbeux, on affiche qui utilise le pattern */
				if (param.verbose != 0)
				{
					funcShowWhoUseIt(infoProcess.listSeg, itSeg, *itItem);
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

/**
** \fn char charOrDot(char c)
** \brief Permet d'afficher les caracteres ASCII ou des '.' sinon
**
** \param c Caractere a afficher
** \return Retourne le caractere si c'est un caractere ASCII, '.' sinon
*/
static char	charOrDot(char c)
{
	if ((isgraph(c)) || (c == ' '))
		return (c);
	return ('.');
}

/**
** \fn void hexDumpData(const char *buffer, unsigned long bufferSize, unsigned long bufferAddr,
**				unsigned long addrDump, unsigned long sizeDump)
** \brief Gere l'affichage de donnees d'un buffer au format "Address: Hexa ASCII"
**
** \param buffer Buffer contenant les donnees a afficher
** \param bufferSize Taille du buffer
** \param bufferAddr Adresse/offset du debut du buffer
** \param addrDump Adresse du debut des donnees a dumper (par rapport a "bufferAddr")
** \param sizeDump Nombre d'octets a afficher
** \return Retourne rien
*/
static void	hexDumpData(const char *buffer, unsigned long bufferSize, unsigned long bufferAddr,
				unsigned long addrDump, unsigned long sizeDump)
{
	/* Gere les underflows et les overflows */
	if (addrDump > (bufferAddr + bufferSize))
		return ;
	if ((addrDump + sizeDump) >= (bufferAddr + bufferSize))
		sizeDump = bufferSize - addrDump;

	/* L'affichage se fait 16 octets par 16 octets */
	for (unsigned long totalBytes=0; totalBytes<sizeDump; totalBytes+=16)
	{
		/* Affiche l'adresse */
		printf("      %lx: ", bufferAddr + totalBytes);

		/* Affiche les octets en hexadecimal */
		for (unsigned long i=0; i<16; i++)
		{
			if ((i % 8) == 0)
				printf("   ");

			if ((totalBytes+i) < sizeDump)
				printf("%02x ", (unsigned char)buffer[addrDump - bufferAddr + totalBytes + i]);
			else
				printf("   ");
		}

		/* Affiche les octets en ascii */
		for (unsigned long i=0; i<16; i++)
		{
			if ((i % 8) == 0)
				printf("   ");

			if ((totalBytes+i) < sizeDump)
				printf("%c", charOrDot(buffer[addrDump - bufferAddr + totalBytes + i]));
			else
				printf("   ");
		}

		printf("\n");
	}
}

/**
** \fn void funcShowWhoUseIt(const std::map<unsigned long, sInfoMem*> &listSeg,
**				const std::map<unsigned long, sInfoMem*>::const_iterator &itSeg,
**				unsigned long offsetPattern)
** \brief Gere l'affichage des endroits de emeoire contenant le pointeur
**
** \param listSeg Liste des segments du processus
** \param itSeg Segment contenant l'offset a chercher en memoire
** \param offsetPattern Offset dans le segment 'itSeg' a chercher en memoire
** \return Retourne rien
*/
static void	funcShowWhoUseIt(const std::map<unsigned long, sInfoMem*> &listSeg,
				const std::map<unsigned long, sInfoMem*>::const_iterator &itSeg,
				unsigned long offsetPattern)
{
	std::map<unsigned long, sInfoMem*>	listWhoUseIt;
	unsigned long				sizeSeg;
	unsigned long				addrSeg;
	const char				*contentSeg;

	/* Affiche les infos de tout les endroits ou le pattern est utilise */
	whoUseIt(listWhoUseIt, listSeg, itSeg->second->addr + offsetPattern);
	for (std::map<unsigned long, sInfoMem*>::iterator itWhoUseIt=listWhoUseIt.begin();
	     itWhoUseIt!=listWhoUseIt.end();
	     itWhoUseIt++)
	{
		sizeSeg = itWhoUseIt->second->size;
		addrSeg = itWhoUseIt->second->addr;
		contentSeg = itWhoUseIt->second->content;

		hexDumpData(contentSeg, sizeSeg, addrSeg, itWhoUseIt->first-(4*16), 4*16);

		/* Affiche l'adresse du pattern */
		printf("      %lx:    %lx\n", itWhoUseIt->first, offsetPattern+itSeg->second->addr);

		hexDumpData(contentSeg, sizeSeg, addrSeg, itWhoUseIt->first+sizeof(unsigned long), 4*16);
		printf("\n");
	}
}

