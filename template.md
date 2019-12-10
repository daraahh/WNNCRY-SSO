---
title: Análisis de malware. WannaCry
subtitle: Seguridad en Sistemas Operativos
author:
  - Darío Abad Tarifa - darioabta@correo.ugr.es
  - Álvaro García Jaén - alvarogj@correo.ugr.es
lang: es
geometry: "left=3cm,right=2cm,top=3cm,bottom=3cm"
toc: True
toc-own-page: True
linkcolor: blue
titlepage: True
listings-no-page-break: True
---

# Introducción

Un ransomware es un tipo de malware que secuestra la información de la víctima y amenaza con publicarla o bloquear su acceso de forma permanente mediante su cifrado a menos que su rescate sea pagado. Dicho pago se hace normalmente a través de criptodivisas como Bitcoin, lo que dificulta el rastreo de los delincuentes.

El ataque sucedido el 12 de mayo de 2017 que tuvo como protagonista al ransomware WannaCry ha sido descrito como sin precendentes y afectó a más de 230.000 computadoras de más de 150 países, incluyendo compañías importantes como Telefónica en España, FedEx e incluso departamentos del servicio nacional de salud de Gran Bretaña.

Es común encontrar descripciones que definen este malware como un criptogusano, esto es debido al comportamiento que refleja y lo que, probablemente, propició el gran alcance del ataque a nivel mundial. Esta característica es algo poco común respecto a otros ransomware, ya que lo normal es que los ataques de este tipo se lleven a cabo mediante troyanos que llegan a los equipos de las víctimas a través de campañas de phishing. Sin embargo WannaCry se expandía de forma automáticamente por los equipos de la red tras la infección de un equipo.

Dicha expansión se llevaba a cabo mediante el uso del exploit *EternalBlue*, que fue revelado por el grupo *The Shadow Brokers* el 14 de abril (1 mes antes del ataque). Dicho exploit se aprovecha de la vulnerabilidad *MS17-010* del protocolo *Server Message Block*. El detalle importante es que Microsoft liberó un parche para esta vulnerabilidad el 14 de marzo (2 meses antes del ataque), sin embargo, es probable que debido al poco margen de tiempo y la falta de concienciación dicha actualización no fuera aplicada en la mayoría de equipos. Una actualización que además no cubría versiones de Windows XP.

Aunque es un ataque de gran gravedad, las consecuencias podrían haber sido peores si no se hubiera descubierto el *kill-switch* que detuvo la propagación o si hubiera sido un ataque dirigido a infraestructuras críticas, como centrales nucleares o eléctricas. Llamamos *kill-switch* al método que tiene un malware de parar su propagación. En el análisis qué hacía el WannaCry para saber si debía propagarse o no.

En este documento se tratará el contexto que acompañaba al suceso, se documentará el funcionamiento del malware, se hablará del impacto que tuvo y la perspectiva actual que se tiene sobre los ataques ransomware. Además se comentarán las diferentes teorías sobre la, poco clara, autoría del ataque y se realizará un análisis técnico de una muestra del malware mediante técnicas de ingeniería inversa.

# Antecedentes

El término ransomware se volvió más y más conocido gracias al famoso WannaCry.
Sin embargo, no debemos olvidar que el WannaCry es uno de tantos ransomware. En
este punto veremos otros muchos que hubo y como fueron evolucionando hasta
llegar a ser uno de los malware más temidos por muchas empresas.

Comenzamos nuestro viaje en 1989, cuando el doctor Joseph Popp, investigador del
SIDA, difundió un troyano haciéndolo pasar por una aplicación que ayudaba a
determinar el riesgo de una persona a contraer dicha enfermedad, por lo cual
esta claro que los más perjudicados por este ataque sería el sistema sanitario. Este malware
permanecía en el ordenador de la víctima de manera pasiva hasta que se activada
y cifraba el nombre archivos de la máquina. Tenía una manera muy curiosa de activarse:
contaba el número de veces que el sistema se había iniciado y, cuando el
contador llevaba a 90, ya no había vuelta atrás. El autor intentaba cubrirse las
espaldas afirmando que, cuando un usuario instalaba este programa, se
comprometía a pagar la licencia del mismo y, si no lo hacía, tendría
consecuencias como que "su ordenador dejará de funcionar como lo hace
normalmente". A un nivel más técnico, la realidad es que se trataba de un
malware bastante rudimentario. En ningún momento se cifraba el contenido de los
archivos, sino que simplemente se cifraba su nombre. Esto hacía que su
recuperación fuera muchísimo más asequible. Aún así, para la época, fue un gran
ataque en un entorno que estaba poco preparado. Este ransomwere recibío el
nombre de *AIDS Trojan* (troyano SIDA).

A raíz de este primer ataque, se desarrollaron otros ya más avanzados como el
CryptoLocker. El primer ataque del que se tuvo constancia fue el 5 de septiembre
de 2013 y hasta junio de 2014 no pudo mitigarse completamente. Afectaba, igual
que el caso anterior, a sistemas Windows (DOS). Es lógico, puesto que la mayoría
de usuarios finales utilizan Windows como sistema operativo, que son los
objetivos últimos de estos ataques. Se propagó mediante correo electrónico y
también mediante máquinas que previamente pertenecian a una botnet. Cifraba
archivos tanto locales como también aquellos a los que podía llegar a través de
la red donde estaba conectado el usuario mediante criptografía asimétrica (RSA).
Esto hacía que, aunque se obteniera la clave con la que el atacante había
cifrado la información de la víctima con técnicas como la ingeniería inversa o
se conociera el *kill-switch* para parar el ransomware, no
se pudieran recuperar los datos cifrados puesto que se necesitaba la clave privada que se
mantenía en los servidores del atacante.


# Funcionamiento del WannaCry

A continuación, estudiaremos como funciona el WannaCry. Para ello, iremos
directamente a la práctica para ver, a nivel de código, qué hacía y cómo.

## Análisis técnico de una muestra

Para el desarrollo de esta parte, se ha realizado un **análisis estático** de una muestra del malware que se encuentra en el repositorio the Github [*TheZoo*](https://github.com/ytisf/theZoo). Las principales herramientas usadas son:

* [**Ghidra**](https://github.com/NationalSecurityAgency/ghidra): Framework de ingeniería inversa desarrollado por la NSA.
* **wrestool**: Herramienta para la extracción de recursos en ejecutables Windows perteneciente al paquete *icoutils*.

El análisis se ha llevado a cabo en un una máquina virtual aislada con sistema operativo *Kali Linux 2019.3*. Aunque es un malware que no funciona en Linux, se considera una buena práctica realizar análisis de malware en equipos aislados y que no tengan un uso compartido. Esto es para evitar infectar un sistema que pueda tener información que nos resulte importante y evitar así contagios en otros equipos de la red local.

El procedimiento que se ha llevado a cabo en el análisis consiste resumidamente en identificar los puntos de entrada del ejecutable, a partir del `main`, inferir el funcionamiento de las funciones usadas por orden y una a una de forma recursiva. Tras llevar a cabo el renombrado de las variables existentes en la función y haber comentado los bloques con el fin de aclarar el flujo de ejecución, se ha dado un nombre característico a cada función que permita conocer la tarea que realiza de forma clara.

Se ha determinado como objetivos de este análisis dos sencillos puntos que permitan ilustrar de forma esquemática y empírica el funcionamiento del malware:

* Encontrar el famoso *kill-switch*, relevante sobretodo para la expansión del malware.
* Realizar el desempaquetado del ejecutable con el fin de extraer los recursos que contiene para poder diferenciar los módulos que componen el malware y como interactúan ente si.

Dicho esto, comenzamos el análisis cargando el *primer* ejecutable en Ghidra. Se trata de un PE32, es decir, un ejecutable para sistemas de 32 bits. Conociendo el funcionamiento de *Portable Executable* debemos identificar la llamada a la función `main` situada al final de la función `entry`. Una vez nos hemos desplazado al `main`, comenzamos el renombrado de variables y funciones para clarificar el funcionamiento de esta primera parte.

![Función main depurada](imgs/wnncry_func_main_bonita.png)

Sin habernos demorado más de 10 minutos, hemos encontrado el *kill-switch* encontrado por Marcus Hutchins, con el que paró el ataque en su día y que, según él, [fue de forma accidental](https://www.malwaretech.com/2017/05/how-to-accidentally-stop-a-global-cyber-attacks.html).

Como vemos en la figura, tenemos una variable con la URL al dominio www[.]iuqerfsodp9ifjapos dfjhgosurijfaewrwergwea[.]com que es copiada a un buffer e inmediatamente después se inicia una conexión y se hace una petición a dicha URL. Después, se comprueba si ha encontrado el dominio o no. Si no lo encuentra, es decir, la conexión falla, el malware continúa la ejecución a través de la función que ha sido llamada `CRYPTOR_REAL_ENTRY()`. Si consigue la conexión, el programa termina su ejecución.

Continuamos el análisis en la función definida como el punto de entrada real del malware. Una vez se ha depurado la función, se puede ver que se comprueba el número de argumentos y que si éste es uno, se continua por una función renombrada como `cocinar_wannacry()`.

![Punto de entrada real](imgs/wnncry_func_real_entry.png)

Es una función bastante simple que contiene únicamente la llamada a otras dos funciones, cuyo análisis completo no se va a incluir en este documento. En definitiva, la primera función, crea un servicio de nombre "mssecvc2.0" que será usado en etapas posteriores por la componente gusano del malware. La segunda función, extrae un recurso (1831) del ejecutable, nombrado *tasksche.exe*, y lo ejecuta.

![*Cocinar* WannaCry](imgs/wnncry_func_cocinar.png)

Para extraer dicho recurso nosotros mismos, se hace uso de la herramienta *wrestool* como se ilustra en la figura. Como se puede comprobar, se trata de otro ejecutable que vamos a cargar en Ghidra para continuar el análisis.

![Extracción del recurso 1831](imgs/wnncry_extract_1831.png)

Cargado el ejecutable, repetimos el procedimiento renombrando variables y funciones de la función `main` obteniendo como resultado lo que aparace en la figura.

![Función main 1813](imgs/wnncry_1813_main.png)

De forma resumida, este ejecutable, primero, va a crear una carpeta oculta generando el nombre a partir del hostname y va crear/arrancar el servicio que se ha comentado en la etapa anterior para asegurar la persistencia. Después, va a crear entradas en el registro que apunten a los ejecutables maliciosos para asegurar la persistencia también y va a extraer una segunda ronda de recursos. Estos recursos están comprimidos en un zip con la contraseña "WNcry@2ol7" y contiene imágenes, textos, traducciones y claves para el cifrado de archivos, además de otros ejecutables. Estos binarios serán ejecutados desde hebras distintas y tienen que ver con la GUI que se presenta a la víctima, utilidades de limpieza de archivos y la expansión del malware mediante EternalBlue.

En resumen, se van a extraer dichos recursos para completar el despezado del malware y poder señalar cada módulo o parte y cómo interactúan entre sí.

![Extracción recurso 2058](imgs/wnncry_2058_files.png)

Los archivos son los siguientes:

* *b.wnry*: Imagen que el malware coloca como fondo de pantalla en la que da indicaciones a la víctima.
* *c.wnry*: Contiene información sobre dominios TOR con los que se comunica el malware.
* *msg/*: Contiene las traducciones del texto que se presenta a la víctima con las instrucciones para recuperar la información.
* *r.wnry*: Más texto informativo para la víctima.
* *s.wnry*: Zip que contiene archivos relacionados con TOR y la comunicación con el C&C.
* *taskdl.exe*: Utilidad de limpieza que el malware utiliza.
* *taskse.exe*: Ejecutable maliciosos usado en la etapa de expansión que explora la red en busca de equipos vulnerables.
* *t.wnry*: Una DLL cifrada que es la que, en realidad, desempeña el cifrado de los archivos del sistema.
* *u.wnry*: Ejecutable que muestra la GUI a la víctima con la cuenta atrás y las instrucciones para el pago del rescate

Por tanto, el malware ejecutaría dos etapas previas al cifrado de archivos en las que realiza acciones que aseguran la persistencia del malware en el sistema y despliega los recursos empaquetados en lugares específicos que después son ejecutados para cifrar los archivos (*t.wnry*), informar a la víctima del secuestro (*u.wnry*) y expandirse a otros equipos mediante el exploit EternalBlue (*taskse.exe*). Este último ejecutable se comunicaría con el servicio creado en una etapa anterior, llamado *mssecvc2.0*, que intentaría enumerar sesiones RDP activas en busca de nuevos equipos.

# Impacto

Como ya hemos mencionado, el WannaCry tuvo un impacto sin precedentes. Se dice
que alrededor 300.000 ordenadores fueron infectados en 150 paises. Russia,
Ucrania, India y Taiwan fueron los paises más afectados.

Al igual que en el primer ransomware conocido, el troyano SIDA, el sistema
sanitario fue una de las partes que salió peor parada, en este caso los
hospitales de el Servicio Nacional de Salud (National Health Service) de
Inglaterra y Escocia. Lo preocupante de todo esto es que no se estaba explotando
un 0-day (Zero-day, vulnerabilidad que el desarrollador ha tenido cero días para
parchear), sino que *EternalBlue* ya había sido reportado. Cabe destacar que los
300.000 ordenadores infectados ocurrió solo en 4 días gracias a que el
*kill-switch* fue descubierto de manera prematura, pero podemos intuir que había
muchas más máquinas desactualizadas (ya no solo que no tenían el último parche de
seguridad, sino que muchos utilizaban Windows XP que no recibía actualizaciones desde 2014.

No debemos olvidar que quien sea que lanzó el ataque, podría haber cambiado
facilmente el *kill-switch* y lanzar una segunda oleada de ransomware cambiando
el dominio que debía comprobar para continuar propagándose, pero por
motivos que desconocemos prefirió dejarlo ahí.

Se estima que las pérdidas económicas de este ransomware rondan los 4 billones
de dolares americanos.

# Atribución del ataque

Tras analizar el ransomware, las pistas apuntan a que el ataque fue realizado
por Corea del Norte. Se basan en los siguientes puntos:

-   La máquina del atacante tenía archivos de *Hangul* instaladas. Esto es el
    alfabeto coreano.
-   Dichos archivos, además contenían metadatos. Estos metadatos establecen que
    el ransomware fue creado en un ordenador que tenía como zona horaria
    UTC+09:00, la zona horaria de Corea.
-   El WannaCry tiene similaridades en cuanto a código con otros malware usado
    en ciber ataques relacionados con Corea del Norte.

Teniendo esto en cuenta, además de más información que probablemente sea
clasificada, Estados Unidos atribuyó publicamente el ataque a Corea del Norte.
Esta obviamente negó su implicación en el mismo.

Es muy dificil saber a ciencia cierta quien realizó el ataque debido al uso de
criptodivisas y a como se propagaba el ataque por las propias máquinas
infectadas. Además, no debe descartarse que todos los puntos citados
anteriormente se hayan dejado a proposito para culpar a Corea del Norte del
ataque por diferentes cuestiones políticas.

# Conclusión

Los ataques ransomware llevados a cabo por WannaCry tuvieron una gran repercusión mediática, quizás desmedida, y generaron una gran alarma social, afectando a grandes compañías que pudieron parecer intocables hasta ese momento.

El caos informático, magnificado por los medios de comunicación y las redes sociales, quizás tuvo algo positivo, esto es que puso a debate el nivel de seguridad de los sistemas que nos rodean a diario y de los que depende nuestro ritmo de vida.

WannaCry no fue un malware realmente sofisticado y, sin embargo, el mundo no estaba preparado.

# Bibliografia

* [WannaCry Ransomware Attack. Wikipedia](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack)
* [AIDS (Trojan horse)](https://en.wikipedia.org/wiki/AIDS_%28Trojan_horse%29)
* [CryptoLocker](https://en.wikipedia.org/wiki/CryptoLocker)
* [First known ransomware attack in 1989 also targeted
  healthcare](https://www.beckershospitalreview.com/healthcare-information-technology/first-known-ransomware-attack-in-1989-also-targeted-healthcare.html)
* [Impact of WannaCry: Major disruption as organisations go back to
  work](https://www.siliconrepublic.com/enterprise/wannacry-impact-organisations-attack)
* [WannaCry Malware Profile. Fireeye](https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html)
* [WannaCry Ransomware: Analysis of Infection, Persistence, Recovery Prevention and Propagation Mechanisms.](https://www.il-pib.pl/czasopisma/JTIT/2019/1/113.pdf)
