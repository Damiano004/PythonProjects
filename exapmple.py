#questa è una funzione maybe
def ciao():
    print("helo")

ciao()
#-------------------------

#questa è una definizione di variabile
a = 10

print (a)
#-------------------------

#questo è un ciclo da x a y
for i in range(3,6):
    print(i)

#-------------------------

#questo è un ciclo da x a y incrementano di z ogni volta
for i in range(3,6,2):
    print(i)

#-------------------------

#questa è un'array
array = [1,2,5,7,9]
    #come si stampa:
for x in array:
    print (x)

#-------------------------

#si può stampare anche cos' WTF
print (array[-1])
#stampa l'ultimo elemento della lista

#-------------------------

#gestione delle eccezioni specifiche
s = "abcdefghijklmno"

for i in range(20):
    try:
        print(s[i])
    except IndexError as e:
        print("Finito gli spazi ",e)

print("fine")
#-------------------------

#come "sollevare" delle eccezioni personalizzate
#così si crea una classe che eredita dalla classe Exception
class PiselloError(Exception):
    '''I guess questa è la cazzo di descrizione dell'errore
    è una stringa che in realà è un commento perché sì...
    (sono molto utili perché dopo VSCode te li mostra se passi sopra alla funzione/classe col mouse)'''

#puoi annotare la tipologia di un parametro (utile solo per rendere più leggibile il codice)
#per assegnare il tipo che una funzione ritorna si fa con "-> 'tipo'"
def test(s:str) -> bool:
    '''uga buga
    raisa PiselloError se la stringa in input non è un cazzo di numero'''
    try:
        n = int(s)
    except ValueError:
        raise PiselloError("U R retarded")
    return n % 2 == 0

for i in range(4):
    print(test(i))
while True:
    #come prendere un input da tastiera (puoi inserire tra parentesi il prompt che vuoi stampare in linea di comando)
    user_input = input("Insert a number: ")
    try:
        #utilizzo la funzione int() per trasformare una stringa nel numero inserito
        output = test(user_input)
    except PiselloError as e:
        print(e)
    #puoi inserire degli else per dire: se non hai trovato eccezoini, fai questo
    else:
        print(f'Is {user_input} even: {output}')
        #questa è una stringa formattata, ovvero inserendo "f'ciao {A}'" se A è uguale a 1 stamperà "Ciao 1"
        break