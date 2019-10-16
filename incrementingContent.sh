#Input ffuf folder and general output folder
ls $1/*.incremental.txt | xargs -I{} cat {} > $2/incrementalContent.txt