#include	"header.h"



/**
** \fn unsigned long getFileDump(const std::string &filename, sInfoProcess &infoProcess)
** \brief Gere la recuperation du contenu d'un fichier
**
** \param filename Nom du fichier a analyser
** \param infoProcess Structure devant contenir les infos du processus a analyser
** \return Retourne le nombre de segments recuperes
*/
unsigned long	getFileDump(const std::string &filename, sInfoProcess &infoProcess)
{
	int		f;
	off_t		size;
	sInfoMem	*ptrSegTmp;

	infoProcess.clear();

	/* Ouvre le fichier "filename" pour acceder a la memoire des segments */
	if ((f = open(filename.c_str(), O_RDONLY)) <= 0)
		printf("Cannot access to \"%s\"\n", filename.c_str());
	else
	{
		if ((size = lseek(f, 0, SEEK_END)) != -1)
		{
			/* Si on a pas deja un segment a cette adresse on le cree */
			if ((size > 0) && (infoProcess.listSeg.find(0) == infoProcess.listSeg.end()))
			{
				if ((ptrSegTmp = new sInfoMem) != NULL)
				{
					infoProcess.listSeg[0] = ptrSegTmp;

					ptrSegTmp->name = filename;
					ptrSegTmp->addr = 0;
					ptrSegTmp->size = size;
					ptrSegTmp->flags = INFOMEM_FLAG_R | INFOMEM_FLAG_W | INFOMEM_FLAG_X;

					if ((ptrSegTmp->content = new char[size+16]) == NULL)
					{
						printf("malloc() error\n");
						exit(0);
					}
					memset(ptrSegTmp->content, 0, size+16);

					/* Recupere le contenu du fichier */
					lseek(f, 0, SEEK_SET);
					read(f, ptrSegTmp->content, ptrSegTmp->size);
				}
			}
		}

		close(f);
	}

	return (infoProcess.listSeg.size());
}

/**
** \fn unsigned long getProcessDump(pid_t pid, sInfoProcess &infoProcess)
** \brief Gere la recuperation du contenu des segments d'un processus
**
** \param pid PID du processus a analyser
** \param infoProcess Structure devant contenir les infos du processus a analyser
** \return Retourne le nombre de segments recuperes
*/
unsigned long	getProcessDump(pid_t pid, sInfoProcess &infoProcess)
{
	char	bufferNameTmp[64];
	int	f;

	/* Recupere les infos des differents segments */
	infoProcess.clear();
	if (getProcessMap(pid, infoProcess) <= 0)
		return (0);

	/* Ouvre le fichier "/proc/[PID]/mem pour acceder a la memoire des segments */
	snprintf(bufferNameTmp, 63, "/proc/%u/mem", pid);
	if ((f = open(bufferNameTmp, O_RDONLY)) <= 0)
	{
		printf("Cannot access to \"%s\"\n", bufferNameTmp);
		infoProcess.clear();
	}
	else
	{
		/* Recupere le contenu des segments */
		for (std::map<unsigned long, sInfoMem*>::iterator itSeg=infoProcess.listSeg.begin();
		     itSeg!=infoProcess.listSeg.end();
		     itSeg++)
		{
			/* Se place a l'adresse du debut du segment */
			if (lseek(f, itSeg->second->addr, SEEK_SET) != (off_t)-1)
			{
				read(f, itSeg->second->content, itSeg->second->size);
			}
		}

		close(f);
	}

	return (infoProcess.listSeg.size());
}

/**
** \fn unsigned long getProcessMap(pid_t pid, sInfoProcess &infoProcess)
** \brief Recupere les infos des segments d'un processus
**
** \param pid PID du processus a analyser
** \param infoProcess Structure devant contenir les infos du processus a analyser
** \return Retourne le nombre de segments recuperes
*/
unsigned long	getProcessMap(pid_t pid, sInfoProcess &infoProcess)
{
	char	bufferNameTmp[64];
	std::ifstream	file;
	std::string	line;
	const char	*ptrTmp;
	unsigned long	addrBeginTmp;
	unsigned long	addrEndTmp;
	unsigned long	sizeTmp;
	unsigned int	flagsTmp;
	sInfoMem	*ptrSegTmp;

	infoProcess.clear();

	/* Ouvre le fichier contenant les infos des segments */
	snprintf(bufferNameTmp, 63, "/proc/%u/maps", pid);
	file.open(bufferNameTmp, std::ifstream::in);
	if (file)
	{
		/* Recupere les infos du processus */
		infoProcess.pid = pid;
		infoProcess.name = getProcessName(pid);

		/* Recupere les infos des segments un par un */
		while (std::getline(file, line))
		{
			ptrTmp = line.c_str();

			/* Adresse de debut */
			addrBeginTmp = strtoul(ptrTmp, (char**)&ptrTmp, 16);
			if (*ptrTmp == '-')
				ptrTmp++;

			/* Adresse de fin + calcul de la taille du segment */
			addrEndTmp = strtoul(ptrTmp, (char**)&ptrTmp, 16);
			sizeTmp = addrEndTmp - addrBeginTmp;
			while (isspace(*ptrTmp))
				ptrTmp++;

			/* Flags */
			flagsTmp = 0;
			while ((*ptrTmp != ' ') && (*ptrTmp != '\t') && (*ptrTmp != '\0'))
			{
				if (*ptrTmp == 'r')
					flagsTmp = flagsTmp | INFOMEM_FLAG_R;
				else if (*ptrTmp == 'w')
					flagsTmp = flagsTmp | INFOMEM_FLAG_W;
				else if (*ptrTmp == 'x')
					flagsTmp = flagsTmp | INFOMEM_FLAG_X;
				ptrTmp++;
			}

			/* Passe la merde */
			while (isspace(*ptrTmp))
				ptrTmp++;
			while ((isspace(*ptrTmp) == 0) && (*ptrTmp != '\0'))
				ptrTmp++;
			while (isspace(*ptrTmp))
				ptrTmp++;
			while ((isspace(*ptrTmp) == 0) && (*ptrTmp != '\0'))
				ptrTmp++;
			while (isspace(*ptrTmp))
				ptrTmp++;
			while ((isspace(*ptrTmp) == 0) && (*ptrTmp != '\0'))
				ptrTmp++;
			while (isspace(*ptrTmp))
				ptrTmp++;

			/* Si on a pas deja un segment a cette adresse, on le cree */
			if ((sizeTmp > 0) && (infoProcess.listSeg.find(addrBeginTmp) == infoProcess.listSeg.end()))
			{
				if ((ptrSegTmp = new sInfoMem) != NULL)
				{
					infoProcess.listSeg[addrBeginTmp] = ptrSegTmp;

					ptrSegTmp->name =  ptrTmp;
					ptrSegTmp->addr =  addrBeginTmp;
					ptrSegTmp->size =  sizeTmp;
					ptrSegTmp->flags =  flagsTmp;

					if ((ptrSegTmp->content = new char[sizeTmp+16]) == NULL)
					{
						printf("malloc() error\n");
						exit(0);
					}
					memset(ptrSegTmp->content, 0, sizeTmp+16);
				}
			}
		}

		file.close();
	}

	return (infoProcess.listSeg.size());
}




/**
** \fn const sInfoMem *getSegmentFromAddr(const std::map<unsigned long, sInfoMem> &mapMemory, unsigned long addr)
** \brief Identifie un segment a partir d'une addresse
**
** \param mapMemory Liste contenant les infos des segments
** \param addr Adresse a chercher
** \return Retourne un pointeur sur le segment contenant l'adresse si OK, NULL sinon
*/
const sInfoMem	*getSegmentFromAddr(const std::map<unsigned long, sInfoMem> &mapMemory, unsigned long addr)
{
	for (std::map<unsigned long, sInfoMem>::const_iterator itSeg=mapMemory.begin();
	     itSeg!=mapMemory.end();
	     itSeg++)
	{
		if ((itSeg->second.addr <= addr) && ((itSeg->second.addr+itSeg->second.size) > addr))
			return (&(itSeg->second));
	}

	return (NULL);
}

/**
** \fn unsigned long countPrintableChar(const char *buffer, unsigned long size, unsigned long offset)
** \brief Compte le nombre de caracteres affichable successifs
**
** \param buffer Buffer contenant les caracteres
** \param size Taille du buffer
** \param offset Offset a partir duquel faire la recherche
** \return Retourne le nombre de caracteres affichable trouves a l'offset indiques
*/
unsigned long	countPrintableChar(const char *buffer, unsigned long size, unsigned long offset)
{
	unsigned long	nbs;

	nbs = 0;
	while ( (offset < size) && (myIsprint(buffer[offset])) )
	{
		offset++;
		nbs++;
	}

	return (nbs);
}

/**
** \fn unsigned long searchString(std::set<unsigned long> &dst, const char *buffer, unsigned long size,
**				unsigned long offset, const char *str)
** \brief Gere la recherche de chaine de caracteres dans un buffer
**
** \param dst Liste ou mettre les offset de chaine trouvee
** \param buffer Buffer ou chercher les donnees
** \param size Taille du buffer ou chercher les donnees
** \param offset Offset a pertir duquel chercher les donnees
** \param str Chaine a chercher
** \return Retourne le nombre d'occurence trouvees
*/
unsigned long	searchString(std::set<unsigned long> &dst, const char *buffer, unsigned long size,
				unsigned long offset, const char *str)
{
	return (searchData(dst, buffer, size, offset, str, strlen(str)));
}

/**
** \fn unsigned long searchStringI(std::set<unsigned long> &dst, const char *buffer, unsigned long size,
**				unsigned long offset, const char *str)
** \brief Gere la recherche de chaine de caracteres dans un buffer (unsensitive)
**
** \param dst Liste ou mettre les offset de chaine trouvee
** \param buffer Buffer ou chercher les donnees
** \param size Taille du buffer ou chercher les donnees
** \param offset Offset a pertir duquel chercher les donnees
** \param str Chaine a chercher
** \return Retourne le nombre d'occurence trouvees
*/
unsigned long	searchStringI(std::set<unsigned long> &dst, const char *buffer, unsigned long size,
				unsigned long offset, const char *str)
{
	char		bufferStr[512];
	char		*ptrStr;
	unsigned long	sizeStr;
	unsigned long	i;

	dst.clear();

	/* La taille de la chaine ne peut pas etre superieure a celle du buffer */
	if ((sizeStr = strlen(str)) >= size)
		return (0);
	size = size - sizeStr;

	/* On cree une copie de la chaine en lowercase pour ne pas faire la conversion plus tard */
	if (sizeStr < 511)
		ptrStr = bufferStr;
	else if ((ptrStr = (char*)malloc(sizeStr + 1)) == NULL)
		return (0);

	for (i=0; i<sizeStr; i++)
		ptrStr[i] = myTolower(str[i]);
	ptrStr[i] = '\0';

	/* Cherche la chaine en boucle */
	while (offset < size)
	{
		/* Filtre les caracteres superieurs a 0x80 et inferieur a 0x20 pour gagner du temps */
		if ( ( (*((uint32_t*)&(buffer[offset])) & 0x80000000) != 0) ||
		     ( (*((uint32_t*)&(buffer[offset])) & 0xe0000000) == 0) )
			offset += sizeof(uint32_t);
		else
		{
			i = 0;
			while ((str[i] != '\0') && (myTolower(buffer[offset+i]) == ptrStr[i]))
				i++;

			if (str[i] == '\0')
			{
				dst.insert(offset);
				offset += sizeStr;
			}
			else
				offset++;
		}
	}

	/* Supprime le buffer si on l'a alloue */
	if (ptrStr != bufferStr)
		free(ptrStr);

	return (dst.size());
}

/**
** \fn unsigned long searchData(std::set<unsigned long> &dst, const char *buffer, unsigned long size,
**				unsigned long offset, const char *data, unsigned long dataSize)
** \brief Gere la recherche de donnees dans un buffer
**
** \param dst Liste ou mettre les offset de chaine trouvee
** \param buffer Buffer ou chercher les donnees
** \param size Taille du buffer ou chercher les donnees
** \param offset Offset a pertir duquel chercher les donnees
** \param data Donnees a chercher
** \param dataSize Taille des donnees a chercher
** \return Retourne le nombre d'occurence trouvees
*/
unsigned long	searchData(std::set<unsigned long> &dst, const char *buffer, unsigned long size,
				unsigned long offset, const char *data, unsigned long dataSize)
{
	const char	*ptrTmp;

	dst.clear();

	while (size > offset)
	{
		ptrTmp = &(buffer[offset]);
		if ((ptrTmp = (const char*)memmem(ptrTmp, size-offset, data, dataSize)) == NULL)
			offset = size;
		else
		{
			dst.insert(ptrTmp - buffer);
			offset = (ptrTmp - buffer) + dataSize;
		}
	}

	return (dst.size());
}

/**
** \fn unsigned long whoUseIt(std::map<unsigned long, sInfoMem*> &dst, const std::map<unsigned long, sInfoMem*> &listSeg,
**				unsigned long addr)
** \brief Gere une adresse dans l'ensemble des segments
**
** \param dst Map ou mettre les occurences de l'adresse (<addr virtuelle, segment*>
** \param listSeg Liste des segments du programme
** \param addr Adresse a chercher en memoire
** \return Retourne le nombre d'occurences decouvertes
*/
unsigned long	whoUseIt(std::map<unsigned long, sInfoMem*> &dst, const std::map<unsigned long, sInfoMem*> &listSeg,
				unsigned long addr)
{
	std::set<unsigned long>	listOffset;

	dst.clear();

	/* Pour tout les segments */
	for (std::map<unsigned long, sInfoMem*>::const_iterator itSeg=listSeg.begin();
	     itSeg!=listSeg.end();
	     itSeg++)
	{
		/* Cherche l'adresse dans le segment */
		searchData(listOffset, itSeg->second->content, itSeg->second->size, 0, (const char*)&addr, sizeof(addr));

		/* Pour toutes les occurence de l'adresse */
		for (std::set<unsigned long>::iterator itItem=listOffset.begin();
		     itItem!=listOffset.end();
		     itItem++)
		{
			dst[itSeg->second->addr + *itItem] = itSeg->second;
		}
	}

	return (dst.size());
}

/**
** \fn unsigned long getEveryRWStrings(sInfoProcess &infoProcess)
** \brief Extrait toutes les chaines des segments RW si "infoProcess.listRWStrings" est vide
**
** \param infoProcess Structure contenant les infos du processus a analyser
** \return Retourne le nombre de chaines extraites
*/
unsigned long	getEveryRWStrings(sInfoProcess &infoProcess)
{
	const char	*ptrContent;
	unsigned long	sizeContent;
	unsigned long	nbsChar;
	std::string	strTmp;

	/* S'il y a deja des strings, on considere que la recherche a deja ete faite */
	if (infoProcess.listRWStrings.size() > 0)
		return (infoProcess.listRWStrings.size());

	/* Pour tout les segments RW */
	for (std::map<unsigned long, sInfoMem*>::const_iterator itSeg=infoProcess.listSeg.begin();
	     itSeg!=infoProcess.listSeg.end();
	     itSeg++)
	{
		if ( ((itSeg->second->flags & INFOMEM_FLAG_R) == INFOMEM_FLAG_R) &&
		     ((itSeg->second->flags & INFOMEM_FLAG_W) == INFOMEM_FLAG_W) &&
		     (itSeg->second->size > SIZE_STRING_MIN) )
		{
			ptrContent = itSeg->second->content;
			sizeContent = itSeg->second->size;

			/* On recupere toutes les chaines de caracteres dans un set */
			for (unsigned long offset=0; offset<sizeContent-SIZE_STRING_MIN; )
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
						strTmp.clear();
						strTmp.append(&(ptrContent[offset]), nbsChar);
						infoProcess.listRWStrings.insert(strTmp);

						offset += nbsChar;
					}
					else
						offset++;
				}
			}
		}
	}

	return (infoProcess.listRWStrings.size());
}

/**
** \fn std::string createDumpFilename(pid_t pid, const std::string &processName, const sInfoMem *seg)
** \brief Gere la preparation d'un nom de fichier de dump
**
** \param pid PID du processus en cours d'analyse
** \param processName Nom du processus en cours d'analyse
** \param seg Segment a utiliser pour preparer le nom de fichier
** \return Retourne une string contenant le nom de fichier
*/
std::string	createDumpFilename(pid_t pid, const std::string &processName, const sInfoMem *seg)
{
	char	bufferFilename[1204];

	snprintf(bufferFilename, 1023, "%s.%u_%lx.%lu.%c%c%c_%s.dump",
		processName.c_str(), pid,
		seg->addr, seg->size,
		((seg->flags & INFOMEM_FLAG_R) ? 'r' : '-'),
		((seg->flags & INFOMEM_FLAG_W) ? 'w' : '-'),
		((seg->flags & INFOMEM_FLAG_X) ? 'x' : '-'),
		seg->name.c_str());

	for (unsigned long i=0; bufferFilename[i]!='\0'; i++)
	{
		if ((isgraph(bufferFilename[i]) == 0) ||
		    (bufferFilename[i] == '/'))
			bufferFilename[i] = '.';
	}

	return (bufferFilename);
}

/**
** \fn int saveSegmentToFile(pid_t pid, const std::string &processName, const sInfoMem *seg)
** \brief Gere l'enregistrement du segment dans un fichier
**
** \param pid PID du processus en cours d'analyse
** \param processName Nom du processus en cours d'analyse
** \param seg Segment a enregistrer
** \return Retourne 1 si OK, 0 sinon
*/
int	saveSegmentToFile(pid_t pid, const std::string &processName, const sInfoMem *seg)
{
	std::string	filename;
	int		f;

	/* Prepare le nom du fichier */
	filename = createDumpFilename(pid, processName, seg);

	/* Cree le fichier de dump */
	if ((f = open(filename.c_str(), O_CREAT | O_TRUNC | O_RDWR, 0644)) > 0)
	{
		write(f, seg->content, seg->size);
		close(f);
		return (1);
	}
	else
		printf("Cannot create dump \"%s\"\n", createDumpFilename(pid, processName, seg).c_str());

	return (0);
}

