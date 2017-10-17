#include	"header.h"



/**
** \fn int identParam(int argc, const char **argv, sUserParam &infoParam)
** \brief Gere l'identifiacation des parametres utilisateur
**
** \param argc Nombre de parametres utilisateur
** \param argv Tableau contenant les parametres utilisateur
** \param infoParam Options selectionees par l'utilisateur
** \return 1 si OK, 0 sinon
*/
int	identParam(int argc, const char **argv, sUserParam &infoParam)
{
	int	haveSelectedAProcess;
	int	haveSelectedAModule;

	/* Initialisation des parametres par defaut */
	haveSelectedAProcess = 0;
	haveSelectedAModule = 0;
	initUserParam(infoParam);

	for (int i=1; i<argc; i++)
	{
		if ((strcmp(argv[i], "-d") == 0) || (strcmp(argv[i], "--dump") == 0))
			infoParam.dump = 1;
		else if ((strcmp(argv[i], "-D") == 0) || (strcmp(argv[i], "--dump-all") == 0))
			infoParam.dumpAll = 1;
		else if ((strcmp(argv[i], "-F") == 0) || (strcmp(argv[i], "--force") == 0))
			infoParam.force = 1;
		else if ((strcmp(argv[i], "-h") == 0) || (strcmp(argv[i], "--help") == 0))
			return (0);
		else if ((strcmp(argv[i], "-v") == 0) || (strcmp(argv[i], "--verbose") == 0))
			infoParam.verbose = 1;

		/* Selection d'un fichier a analyser */
		else if ((strcmp(argv[i], "-f") == 0) || (strcmp(argv[i], "--file") == 0))
		{
			if (haveSelectedAProcess == 0)
				infoParam.listPid.clear();
			haveSelectedAProcess = 1;

			if ((i + 1) >= argc)
				return (0);

			i++;
			infoParam.listFiles.insert(argv[i]);
		}

		/* Selection d'un processus a analyser */
		else if ((strcmp(argv[i], "-p") == 0) || (strcmp(argv[i], "--pid") == 0))
		{
			if (haveSelectedAProcess == 0)
				infoParam.listPid.clear();
			haveSelectedAProcess = 1;

			if ((i + 1) >= argc)
				return (0);

			i++;
			if (checkAccessToProcess(atoi(argv[i])) <= 0)
				printf("Cannot analyse process %u\n", atoi(argv[i]));
			else
				infoParam.listPid.insert(atoi(argv[i]));
		}

		/* Selection d'un processus a analyser */
		else if ((strcmp(argv[i], "-P") == 0) || (strcmp(argv[i], "--process-name") == 0))
		{
			if (haveSelectedAProcess == 0)
				infoParam.listPid.clear();
			haveSelectedAProcess = 1;

			if ((i + 1) >= argc)
				return (0);

			i++;
			if (identProcessByName(infoParam, argv[i]) <= 0)
				printf("Cannot find process \"%s\"\n", argv[i]);
		}

		/* Selection des modules */
		else if (didUserSelectAModule(infoParam, argv[i], haveSelectedAModule) > 0)
		{
			haveSelectedAModule = 1;
		}

		/* Sinon, on considere qu'il s'agit d'un pattern a rechercher */
		else if (strlen(argv[i]) > 0)
		{
			if (haveSelectedAModule == 0)
				infoParam.listFunctions.clear();
			haveSelectedAModule = 1;

			infoParam.listPatterns.insert(argv[i]);
			infoParam.listFunctions.insert(&moduleSearchStringExec);
		}
		else
			return (0);
	}

	return (1);
}

/**
** \fn int initUserParam(sUserParam &infoParam)
** \brief Gere l'initialisation par defaut des parametres utilisateur
**
** \param infoParam Parametres a initialiser
** \return Retourne toujours 0
*/
int	initUserParam(sUserParam &infoParam)
{
	DIR		*dir;
	struct dirent	*dirEntry;
	pid_t		pidProcess;

	/* Par defaut, on traite tout les PID des processus auquel on a access */
	infoParam.listFiles.clear();
	infoParam.listPid.clear();
	if ((dir = opendir("/proc/")) != NULL)
	{
		while ((dirEntry = readdir(dir)) != NULL)
		{
			pidProcess = atoi(dirEntry->d_name);
			if (((dirEntry->d_type & DT_DIR) == DT_DIR) && (pidProcess > 0))
			{
				/* Verifie que l'on a acces au processus */
				if (checkAccessToProcess(pidProcess) > 0)
				{
					infoParam.listPid.insert(pidProcess);
				}
			}
		}

		closedir(dir);
	}

	/* Par defaut, tout les modules sont actifs */
	infoParam.listFunctions.clear();
	loadDefaultModule(infoParam);

	infoParam.listPatterns.clear();
	infoParam.verbose = 0;
	infoParam.dump = 0;
	infoParam.dumpAll = 0;
	infoParam.force = 0;

	return (0);
}

/**
** \fn int checkAccessToProcess(pid_t pid)
** \brief Verifie que l'on peut acceder a la memoire d'un processus
**
** \param pid PID du processus
** \return Retourne 1 si OK, 0 sinon
**/
int	checkAccessToProcess(pid_t pid)
{
	struct stat	infoStat;
	char		bufferNameTmp[64];

	snprintf(bufferNameTmp, 63, "/proc/%u", pid);
	if ( (stat(bufferNameTmp, &infoStat) == 0) &&
	     (pid != getpid()) &&
	     ((infoStat.st_uid == geteuid()) || (getuid() == 0)) )
	{
		return (1);
	}

	return (0);
}

/**
** \fn unsigned long identProcessByName(sUserParam &infoParam, const char *name)
** \brief Gere l'identification de processus a partir de leur nom
**
** \param infoParam Structure ou mettre les PID des processus selectionees
** \param name Nom du processus
** \return Retourne le nombre de processus selectionnes
*/
unsigned long	identProcessByName(sUserParam &infoParam, const char *name)
{
	DIR		*dir;
	struct dirent	*dirEntry;
	unsigned long	nbsSelectedProcess;
	std::string	nameProcessTmp;

	/* Parcours tout les processus a la recherche de ceux ayant un nom correspondant */
	nbsSelectedProcess = 0;
	if ((dir = opendir("/proc/")) != NULL)
	{
		while ((dirEntry = readdir(dir)) != NULL)
		{
			if (((dirEntry->d_type & DT_DIR) == DT_DIR) && (atoi(dirEntry->d_name) > 0))
			{
				/* Verifie que l'on a acces au processus */
				if (checkAccessToProcess(atoi(dirEntry->d_name)) > 0)
				{
					/* Regarde si le nom de l'executable correspond a celui que l'on cherche */
					nameProcessTmp = getProcessName(atoi(dirEntry->d_name));
					if (strcmp(nameProcessTmp.c_str(), name) == 0)
					{
						infoParam.listPid.insert(atoi(dirEntry->d_name));
						nbsSelectedProcess++;
					}
				}
			}
		}

		closedir(dir);
	}

	return (nbsSelectedProcess);
}

/**
** \fn std::string getProcessName(pid_t pid)
** \brief Gere la recuperation du nom de l'executable ayant servi a creer un processus
**
** \param pid PID du processus auquel recuperer les nom
** \return Retourne le nom de l'executable si OK, "" sinon
*/
std::string	getProcessName(pid_t pid)
{
	std::string	ret;
	char		bufferNameTmp[64];
	int		f;
	char		bufferTmp[1024];
	std::string	line;
	unsigned long	offset;

	snprintf(bufferNameTmp, 63, "/proc/%u/cmdline", pid);
	if ((f = open(bufferNameTmp, O_RDONLY)) > 0)
	{
		memset(bufferTmp, 0, 1024);
		if (read(f, bufferTmp, 1023) > 0)
		{
			line = bufferTmp;
			if ((offset = line.find_first_of(" \t\n\r")) != std::string::npos)
				line.erase(offset, -1);
			if ((offset = line.find_last_of("/")) != std::string::npos)
				line.erase(0, offset+1);

			ret = line;
		}

		close(f);
	}

	return (ret);
}

/**
** \fn int usage(const char **argv)
** \brief Affiche le message d'aide et retourne 0
**
** \param argv Tableau contenant les parametres utilisateurs
** \return Retourne toujours 0
*/
int	usage(const char **argv)
{
	printf("Usage: %s [options] [module names] [patterns]\n", argv[0]);
	printf("\n");
	printf("Examples :\n");
	printf("  %s\n", argv[0]);
	printf("  %s -p 1234 --thunderbird --basic-auth\n", argv[0]);
	printf("  %s -P thunderbird 'password:'\n", argv[0]);
	printf("\n");

	/* Affiche les options supportees */
	printf("Options :\n"); 
	printf("  -d/--dump                : Dump interesting segments.\n");
	printf("  -D/--dump-all            : Dump every segments.\n"); 
	printf("  -f/--file <filename>     : Load and analyze the file.\n"); 
	printf("  -F/--force               : Force execution for modules who have a \"name\" filter.\n"); 
	printf("  -h/--help                : Print a summary of the options and exit.\n"); 
	printf("  -p/--pid <PID>           : Analyze the process \"PID\".\n"); 
	printf("  -P/--process-name <name> : Analyze the process \"name\".\n"); 
	printf("  -v/--verbose             : Activate verbose mode (only useful for patterns and some modules).\n"); 
	printf("\n");

	/* Affiche les infos des modules */
	printf("Modules :\n");
	for (unsigned long i=0; tabInfoModule[i].fExec!=NULL; i++)
	{
		if ((tabInfoModule[i].option != NULL) && (strlen(tabInfoModule[i].option) > 0))
		{
			printf("  %s\t : %s\n", tabInfoModule[i].option, tabInfoModule[i].info);
		}
	}
	printf("\n"); 

	return (0);
}

