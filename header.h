#ifndef	HEADER_H
#define	HEADER_H

#include	<string>
#include	<list>
#include	<map>
#include	<set>
#include	<fstream>

#include	<stdlib.h>
#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<fcntl.h>
#include	<dirent.h>
#include	<stdint.h>
#include	<time.h>
#include	<arpa/inet.h>

#include	"utils/isPrint.h"


/*
** Permissions des segments
*/
#define	INFOMEM_FLAG_R	1
#define	INFOMEM_FLAG_W	2
#define	INFOMEM_FLAG_X	4

/*
** Pour les couleurs
*/
#define	COLOR_RED	"\033[0;31m"
#define	COLOR_NC	"\033[0m"

/*
** Taille minimum des chaines de caracteres a extraires
*/
#define	SIZE_STRING_MIN	sizeof(uint32_t)


/**
** \class sInfoMem
** \brief Contient les informations d'un segment memoire de processus
*/
class	sInfoMem
{
public:
	sInfoMem():
		name(), addr(0), size(0), flags(0), content(NULL) {}
	~sInfoMem()
	{
		delete[] this->content;
	}

public:
	/* Nom du segment en memoire */
	std::string	name;
	/* Adresse du segment en memoire */
	unsigned long	addr;
	/* Taille du segment en memoire */
	unsigned long	size;
	/* Permissions du segment en memoire */
	unsigned int	flags;
	/* Contenu du segment */
	char		*content;
};

/**
** \class sInfoProcess
** \brief Contient les infos d'un processus en cours d'analyse
*/
class	sInfoProcess
{
public:
	void	clear()
	{
		this->name.clear();
		this->pid = 0;
		
		for (std::map<unsigned long, sInfoMem*>::iterator itSeg=this->listSeg.begin();
		    itSeg!=this->listSeg.end();
		    itSeg++)
			delete itSeg->second;

		this->listSeg.clear();
		this->listRWStrings.clear();
	}

public:
	/** Nom du processus */
	std::string				name;
	/** PID du processus */
	pid_t					pid;
	/** Liste des segments du processus */
	std::map<unsigned long, sInfoMem*>	listSeg;
	/** Set contenant les strings extraites des segments RW du processus */
	std::set<std::string>			listRWStrings;
	/** Juste pour pouvoir afficher le nom du module grace a son pointeur de fonction */
	void					*ptrCurrentModule;
};


/**
** \struct sUserParam
** \brief Contient les options selectionees par l'utilisateur
*/
struct	sUserParam
{
	/* Liste des PID a traiter */
	std::set<pid_t>							listPid;
	/* Liste des fichiers a traiter */
	std::set<std::string>						listFiles;
	/* Liste des fonctions d'analyse a utiliser */
	std::set<unsigned long(*)(sInfoProcess&, const sUserParam&)>	listFunctions;
	/* Liste des regex en cas de recherche de chaines de caracteres */
	std::set<std::string>						listPatterns;
	/* Le mode verbose est il actif ? */
	int								verbose;
	/* Faut il dumper les segments contenant les infos */
	int								dump;
	/* Faut il dumper tous les segments */
	int								dumpAll;
	/* Faut il forcer l'execution des modules sur tout les processus */
	int								force;
};

/**
** \fn struct sInfoModule
** \brief Structure contenant les infos des modules
*/
struct	sInfoModule
{
	/** Nom du module */
	const char	*name;
	/** Option a utiliser pour selectionner le module */
	const char	*option;
	/** Faut-il utiliser ce module par defaut */
	int		useByDefault;
	/** Pointeur vars la fonction permettant d'executer le module */
	unsigned long	(*fExec)(sInfoProcess&, const sUserParam&);
	/** Manuel du module */
	const char	*info;
};

/*
** identParam.cpp
*/
int		identParam(int argc, const char **argv, sUserParam &infoParam);
int		initUserParam(sUserParam &infoParam);
int		checkAccessToProcess(pid_t pid);
unsigned long	identProcessByName(sUserParam &infoParam, const char *name);
std::string	getProcessName(pid_t pid);
int		usage(const char **argv);

/*
** dumpMemory.cpp
*/
unsigned long	getFileDump(const std::string &filename, sInfoProcess &infoProcess);
unsigned long	getProcessDump(pid_t pid, sInfoProcess &infoProcess);
unsigned long	getProcessMap(pid_t pid, sInfoProcess &infoProcess);
const sInfoMem	*getSegmentFromAddr(const std::map<unsigned long, sInfoMem*> &listSeg, unsigned long addr);
unsigned long	countPrintableChar(const char *buffer, unsigned long size, unsigned long offset);
unsigned long	searchString(std::set<unsigned long> &dst, const char *buffer, unsigned long size,
				unsigned long offset, const char *str);
unsigned long	searchStringI(std::set<unsigned long> &dst, const char *buffer, unsigned long size,
				unsigned long offset, const char *str);
unsigned long	searchData(std::set<unsigned long> &dst, const char *buffer, unsigned long size,
				unsigned long offset, const char *data, unsigned long dataSize);
unsigned long	whoUseIt(std::map<unsigned long, sInfoMem*> &dst, const std::map<unsigned long, sInfoMem*> &listSeg,
				unsigned long addr);
unsigned long	getEveryRWStrings(sInfoProcess &infoProcess);
std::string	createDumpFilename(pid_t pid, const std::string &processName, const sInfoMem *seg);
int		saveSegmentToFile(pid_t pid, const std::string &processName, const sInfoMem *seg);

/*
** module.cpp
*/
void		loadDefaultModule(sUserParam &infoParam);
int		didUserSelectAModule(sUserParam &infoParam, const char *arg, int alreadeyHaveSelectedAModule);
int		printModuleName(sInfoProcess &infoProcess);

/*
** Fonctions d'analyse
*/
unsigned long	moduleAuthBasicExec(sInfoProcess &infoProcess, const sUserParam &param);
unsigned long	moduleFTPExec(sInfoProcess &infoProcess, const sUserParam &param);
unsigned long	moduleParamHttpExec(sInfoProcess &infoProcess, const sUserParam &param);
unsigned long	moduleSearchStringExec(sInfoProcess &infoProcess, const sUserParam &param);
unsigned long	moduleShadowExec(sInfoProcess &infoProcess, const sUserParam &param);
unsigned long	moduleEtcShadowExec(sInfoProcess &infoProcess, const sUserParam &param);
unsigned long	moduleSmbExec(sInfoProcess &infoProcess, const sUserParam &param);
unsigned long	moduleStringsExec(sInfoProcess &infoProcess, const sUserParam &param);
unsigned long	moduleThunderbirdExec(sInfoProcess &infoProcess, const sUserParam &param);

/*
** Tableau contenant les infos des differents modules pouvant etre utilises
*/
const sInfoModule	tabInfoModule[] =
{
	{
		"Auth-Basic", "--auth-basic", 1,
		&moduleAuthBasicExec,
		"Extract \"Authorization: Basic Base64=\" credentials from RW segments."
	},
	{
		"FTP", "--ftp", 1,
		&moduleFTPExec,
		"Extract \"FTP\" credentials (\"user abc\" and \"pass abc\") from RW segments.\n"
		"\t\tBy default, it only analyzes \"*ftp*\" processes."
	},
	{
		"Param HTTP", "--param-http", 1,
		&moduleParamHttpExec,
		"Extract passwords from URL-style strings from RW segments.\n"
		"\t\tIt search keywords \"password\", \"passwd\", \"pass\" and \"pwd\"."
	},
	{
		"Patterns", "", 1,
		&moduleSearchStringExec,
		"."
	},
	{
		"Hash shadow", "--shadow", 1,
		&moduleShadowExec,
		"Extract hashes at \"/etc/shadow\" format from RW segments.\n"
		"\t\t(Better when launched as root)." 
	},
	{
		"Hash shadow (/etc/shadow)", "--etc-shadow", 1,
		&moduleEtcShadowExec,
		"Read \"/etc/shadow\" hashes and search the corresponding passwords in RW segments.\n"
		"\t\tBy default, it only analyzes the following processes :\n"
		"\t\t - \"*gdm-session-worker*\"\n"
		"\t\t - \"*gnome-keyring*\"\n"
		"\t\t - \"*gnome-shell*\"\n"
		"\t\t - \"*lightdm*\"\n"
		"\t\t(Need to be launched as root)." 
	},
	{
		"Samba", "--smb", 1,
		&moduleSmbExec,
		"Extract NTMLv2 challenge/response info from RW segments and search the corresponding passwords in memory.\n"
		"\t\tIt will also display unresolved challenge/response."
	},
	{
		"Strings", "--strings", 0,
		&moduleStringsExec,
		"Extract strings from every segments (deactivated by default)."
	},
	{
		"Thunderbird", "--thunderbird", 1,
		&moduleThunderbirdExec,
		"Extract IMAP \"normal\" authentication passwords from RW segments.\n"
		"\t\tBy default, it only analyzes \"*mail*\", \"*imap*\" and \"*thunderbird*\" processes."
	},
	{
		NULL, NULL, 0, NULL, NULL
	}
};

#endif
