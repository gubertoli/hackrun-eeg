import subprocess
import os
import time

os.system("clear")
print "\n\n"
print "    .___                               "
print "  __| _/________  _  _____  __________ "
print " / __ |\_  __ \ \/ \/ /\  \/  /\_  __ \\"
print "/ /_/ | |  | \/\     /  >    <  |  | \/"
print "\____ | |__|    \/\_/  /__/\_ \ |__|   "
print "     \/                      \/        "
print "\n"
print "        EEG HackRUN Assessment         \n"
print "          RoadSec SP 2016              \n\n"
print "       contact: www.drwxr.org          \n\n"
nome = raw_input("> Digite o nome do participante: ")
dob = raw_input("> Digite sua idade: ")
grade = raw_input("> Em uma escala de 1 a 5, qual seus conhecimentos de hacking: ")
autho = raw_input("> Autoriza a coleta de dados serem usadas em estudos futuros? [S/N] ")

if (nome <> "" and (int(dob) > 5 and int(dob)<99) and (int(grade) >= 1 and int(grade) <= 5) and (autho == "S" or autho == "s")):
    output_file = file('testCasesEEG.txt','a');
    out = "*;"+str(nome) + ";" + str(dob) + ";" + str(grade) +";"+str(autho)+"\n"
    output_file.write(out)
    output_file.close()
    
    confirma = raw_input("> O headset esta instalado no usuario corretamente? [S/N] ")

    if (confirma == "S" or confirma == "s"):
	print "\n> Iniciando teste...\n\n"
	#os.system("python mindwave/read_mindwave_mobile.py &")
	proc = subprocess.Popen(['python', 'read_mindwave.py'])
	#os.system("python server.py")
	proc2 = subprocess.Popen(['python', 'server.py'])
	time.sleep(7)
	os.system("clear")
	os.system("telnet localhost 4000")
	#print("\n\n> Acesse o desafio no navegador ! ");
	#parar = raw_input("Pressione [ENTER] para encerrar o teste");
	#if (parar <> ""):
	    #os.system("telnet localhost 4000")
	proc2.terminate()
	proc.terminate()
	print "\n> Teste encerrado com sucesso!\n"
else:
    print "[ERRO] Preenchimento incorreto!"
