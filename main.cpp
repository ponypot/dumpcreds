#include	"header.h"



/**
** \fn unsigned long analyseSegments(sUserParam &userParam, sInfoProcess &infoProcess)
** \brief Gere l'analyse des segments grace aux fonctions selectionnees
**
** \param userParam Structure contenant les parametres utilisateurs
** \param infoProcess Structure contenant les infos du processus a analyser
** \return Retourne le nombre d'elements trouves
*/
unsigned long	analyseSegments(sUserParam &userParam, sInfoProcess &infoProcess)
{
	unsigned long	nbsResult;

	nbsResult = 0;

	/* Utilise tout les fonctions d'analyse selectionnees */
	for (std::set<unsigned long(*)(sInfoProcess&, const sUserParam&)>::const_iterator itFunction=userParam.listFunctions.begin();
	     itFunction!=userParam.listFunctions.end();
	     itFunction++)
	{
		infoProcess.ptrCurrentModule = (void*)(*itFunction);
		nbsResult += (*itFunction)(infoProcess, userParam);
	}

	/* Cree les fichiers de dump si besoin est */
	if (userParam.dumpAll != 0)
	{
		/* Pour tout les segments */
		nbsResult = 0;
		for (std::map<unsigned long, sInfoMem*>::const_iterator itSeg=infoProcess.listSeg.begin();
		     itSeg!=infoProcess.listSeg.end();
		     itSeg++)
		{
			if (saveSegmentToFile(infoProcess.pid, infoProcess.name, itSeg->second) <= 0)
				printf("Cannot create dump \"%s\"\n", createDumpFilename(infoProcess.pid, infoProcess.name, itSeg->second).c_str());
		}
	}

	return (nbsResult);
}

/**
** \fn int main(int argc, const char **argv)
** \brief Main de l'extracteur de credentials
**
** \param argc Nombre de parametres utilisateur
** \param argv Tableau contenant les parametres utilisateurs
** \return Retourne 0 si OK, 1 sinon
*/
int	main(int argc, const char **argv)
{
	sUserParam	userParam;
	sInfoProcess	infoProcess;
	unsigned long	nbsResult;

	/* Identifie les parametres */
	if (identParam(argc, argv, userParam) <= 0)
		return (usage(argv));

	/* Traite tout les fichiers */
	nbsResult = 0;
	for (std::set<std::string>::const_iterator itFiles=userParam.listFiles.begin();
	     itFiles!=userParam.listFiles.end();
	     itFiles++)
	{
		printf("Fichier \"%s\"\n", itFiles->c_str());

		/* Recupere le contenu du fichier */
		if (getFileDump(*itFiles, infoProcess) > 0)
		{
			nbsResult += analyseSegments(userParam, infoProcess);
			infoProcess.clear();
		}
	}

	/* Traite tout les processus */
	for (std::set<pid_t>::const_iterator itPid=userParam.listPid.begin();
	     itPid!=userParam.listPid.end();
	     itPid++)
	{
		printf("Process %u (%s)\n", *itPid, getProcessName(*itPid).c_str());

		/* Recupere le contenu de la memoire du processus */
		if (getProcessDump(*itPid, infoProcess) > 0)
		{
			nbsResult += analyseSegments(userParam, infoProcess);
			infoProcess.clear();
		}
	}

	/* Affiche le nombre d'infos recuperees */ 
	printf("Nbs dumped items: %lu\n", nbsResult);

	return (0);
}

