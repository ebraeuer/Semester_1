# Aufgaben zur Funktionsweise von Computer
# Die folgenden Aufgaben greifen den folgenden Videos etwas voraus,
# wie Funktionen etc. Dennoch sollen Funktionen, Kontrollstrukturen und 
# Schleifen jetzt schon mal angewendet werden, um suzzesive den 
# Einstieg in die Programmiersprache Python zu erlangen.
# Versuchen Sie die folgenden Beispiele zu verstehen und sie zur Lösung der
# Aufagben zu nutzen. 
#
# Hinweis: Führen Sie stets das Skript -ähnlich wie das HelloWorld-Example- 
# kontinuierlich aus um jede kleine Veränderung zu beobachten und um Fehler
# frühzeitig zu erkennen. 

# Beispiel für eine Kontrollstruktur (if-else-Anweisung)
#num = 4
#if num >= 4: 
    #print(f"The variable num is grather than 4. ")
#elif num==4:
    #print(f"The variable num is equal 4. ")
#else:
    #print(f"The variable num is smaller than 4. ")

# Beispiel für while-Schleifen 
#length = 5
#tmp    = 0
###
# for tmp in range(length):
    #print(f"{tmp}")

# Beipsiel für eine Funktion: 
# Ein paar Begriffe noch: 
# a und b nennt man Übergabeparameter der Funktion
# my_add ist der Funktionsname (dieser wird auch verwendet, um die Funktion aufzurufen)
# return beschreibt den Rückgabewert (in diesem Fall c) der Funktion. 
def my_add(a, b):
    c = a + b
    return c

num1 = 3
num2 = 4
#sum_of_num = my_add(num1,num2)
#print(f"The return value of function my_add is {sum_of_num}")

### Aufgaben: 
# 1. Schreiben Sie eine Funktion "age_category", mit dem Übergabeparameter "alter". 
# Abhängig von "alter" sind die folgenden Strings zurück zu geben: 
# Verwenden Sie folgende Kategorien:
# Alter < 13: "Kind"
# 13 ≤ Alter < 18: "Jugendlich"
# 18 ≤ Alter < 65: "Erwachsener"
# Alter ≥ 65: "Senior"
# Beispiel: Wenn das Alter 16 ist, soll die Funktion "Jugendlich" zurückgeben.



#alter = 30

#if alter < 13:
#   print("Kind")

#elif alter <18:
#    print("Jugendlich")

#elif alter <65:
#    print("Erwachsen")

#else:

#    print("Senior")









# 2. Schreiben Sie eine Funktion "grade", das eine Zahl (0 bis 100) übernimmt
# (Übergabeparameter) und eine Note ausgibt. Verwenden Sie dazu die folgende
# Notenverteilung:
# 90-100: "Sehr gut"
# 75-89: "Gut"
# 50-74: "Befriedigend"
# 0-49: "Ungenügend"
# Beispiel: Bei einer Eingabe von 85 soll die Funktion "Gut" zurückgeben.


punkte = 49

def grade(punkte):
    if punkte < 50:
        return "Ungenügend"
    elif punkte < 75:
        return "Befriedigend"
    elif punkte < 90:
        return "Gut"
    else:
        return "Sehr gut"

print(grade(punkte))
# 3. Schreiben Sie eine Funktion "odd_even" 
# (ohne Übergabeparameter = Leere Klammer), die alle Zahlen von 1 bis 20 
# durchläuft und anzeigt (print), ob eine Zahl gerade oder ungerade ist.
# Beispielausgabe:
# 1 ist ungerade
# 2 ist gerade
# 3 ist ungerade
# ...


def odd_even ():
    
# 4. Schreiben Sie eine Funktion "mul_tab", die eine Zahl von 1 bis 10 
# übernimmt und die eine entsprechende Multiplikationstabelle für diese Zahl 
# bis 10 berechnet. Beispiel: Für die Eingabe 3 sollte die Funktion folgendes 
# ausgeben:
# 3 x 1 = 3
# 3 x 2 = 6
# ...
# 3 x 10 = 30

# 5. Schreiben Sie eine Funktion, die alle Zahlen von 1 bis 100 summiert und die Gesamtsumme zurück gibt. 

    
#6. Schreiben Sie eine Funktion "quadrat", die eine Zahl als Parameter nimmt 
# und das Quadrat dieser Zahl zurückgibt.
# Beispiel: quadrat(5) sollte 25 zurückgeben.

# 7. Schreiben Sie eine Funktion "fibonacci", die eine Zahl n als Parameter 
# nimmt und die ersten n Zahlen der Fibonacci-Folge ausgibt.
# Beispiel: fibonacci(5) sollte [0, 1, 1, 2, 3] ausgeben.

# Schreiben Sie eine Funktion "ist_primzahl", die eine Zahl als Parameter nimmt 
# und prüft, ob diese Zahl eine Primzahl ist.
# Die Funktion soll True zurückgeben, wenn die Zahl eine Primzahl ist, und 
# ansonsten False.
# Beispiel: ist_primzahl(7) sollte True zurückgeben, ist_primzahl(10) sollte False zurückgeben.