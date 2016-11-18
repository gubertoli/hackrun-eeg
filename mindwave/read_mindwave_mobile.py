import time
import bluetooth
from datetime import datetime
from MindwaveDataPoints import EEGPowersDataPoint, RawDataPoint, MeditationDataPoint, AttentionDataPoint
from MindwaveDataPointReader import MindwaveDataPointReader



if __name__ == '__main__':
    mindwaveDataPointReader = MindwaveDataPointReader()
    mindwaveDataPointReader.start()
    out = ""

    print "\n> Gravando dados EEG...\n"
    while(True):
        dataPoint = mindwaveDataPointReader.readNextDataPoint()
	if (dataPoint.__class__ is MeditationDataPoint):
	    out = str(dataPoint)
	    #print dataPoint
	elif (dataPoint.__class__ is AttentionDataPoint):
	    out = out + ";" + str(dataPoint)
	    #print dataPoint
        #else (not dataPoint.__class__ is RawDataPoint):
	elif (dataPoint.__class__ is EEGPowersDataPoint):
	    out = datetime.strftime(datetime.now(), '%d-%b-%Y %H:%M:%S')+";"+out + ";" + str(dataPoint) + "\n"
	    #print out
	    output_file = file('testCasesEEG.txt','a')
	    output_file.write(out)
	    out = ""
	    output_file.close()
print "\n> Fim da gravacao de dados EEG!\n"
