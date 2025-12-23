# Aufgaben zur Funktionsweise von Computer
# Allgemeiner Hinweis: Ein Import von Modulen ist für die Lösung der Aufgaben
# nicht erforderlich. 

# 1. Addition und Subtraktion
# Definieren Sie die Variablen num1 und num2 mit 2 beliebigen Zahlenwerten. 
# Errechnen Sie aus beiden die Summe und weißen Sie das Ergebnis der Variable
# sum1 zu. 
# Berechnen Sie zudem die Differenz aus num1 und num2 und weißen Sie das Ergebnis
# der Variable diff1 zu. 
wert1 = 0b1010
wert2 = 0b10100 
wert3 =55 
wert4 =44
num1 =3
num2 =18
num3 =6

sum1 = wert1 + wert2
diff1 = wert1 - wert2 
###print(f"{num1} / {num2} = {num1 / num2}")
#print(sum1)
#print(f"{sum1:#b}")
#print(diff1)

# 2. Multiplikation und Division
# Berechnen Sie aus num1 und num2 das Produkt und speichern Sie das Ergebnis
# unter der Variable prod1. Berechnen Sie zusätzlich den Quotienten aus num1 und 
# num2 und speichern Sie das Ergebnis unter der Variable quot1. 
prod1 = wert3 * wert4
quot1 = wert4 / wert3

#print (prod1)
#print (quot1)


# 3. Modulus
# Definieren Sie die Variablen num3 (gerade) und num4 (ungerade) mit positiven 
# ganzzahligen Werten, einer geraden und einer ungeraden Zahl. Berechnen Sie mit
# hilfe der Modulo-Operation (weitere Infos unter 
# https://de.wikipedia.org/wiki/Division_mit_Rest#Modulo), in Python durch 
# das %-Zeichen implementiert (siehe auch 
# https://docs.python.org/3/library/operator.html#module-operator) den Rest bei 
# einer Division beider Zahlen (num3 und num4) durch 2. Speichern Sie das 
# Ergebnis unter mod3 und mod4. 
# Erklären Sie nochmal mit Ihren eigenen Worten, als String der
# Variable exp1, wie die Ergebnisswerte von mod3 und mod4 im Bezug auf die 
# Modulo-Operation mit dem Wert 2 zu interpretieren sind. 
num5 = 82
num6 = 53

mod3 = num5 % 8,7
mod4 = num6 % 2

#print(mod3)
#print (mod4)

# 4. Exponent
# Berechnen Sie die Potenz aus den Zahlen num3 (Basis) und num4 (Exponent) und
# speichern Sie das Ergebnis unter exp4. 
exp1= 3

exp4 = num6 ** exp1

print(exp4)
# 4. Kombinierte arithmetische Operationen 
# Schreiben Sie in einer Code-Zeile die folgende Berechnung und weisen Sie das 
# Ergebnis der Variable res4 zu. Dividieren Sie die Summe von num1 und num2
# durch num3. 

res4 = (num1 + num2) / num3
#print( res4)
gerundet = round(res4, 3)

#print (gerundet)

# 5. Fläche und Umfang
# num3 und num4 sind die Seitenkanten eines Rechtecks. Berechnen Sie die Fläche
# und den Umfang des Rechtecks und speichern Sie die Ergebnisse unter den 
# Variablen area and perimeter. 

area = num1*num2
perimeter = 2*num1 + 2*num2
#print(f"{area}FE")
#print(f"Umfang = {perimeter}cm")


# 6. Mittelwert
# Berechnen Sie den Mittelwert aus den Werten num1, num2, num3 und num4 und
# speichern Sie das Ergebnis unter der Variable average.


#average = 1 /4 (num1 + num2 + num3)

# 7. Berechnung eines Funktionswerts
# Gegeben ist eine lineare Funktion mit der Steigung -2.5 und dem y-Achsen-
# abschnitt 7. Berechnen Sie für den x-Wert -4.5 den Funktionswert und speichern
# Sie das Ergebnis unter der Variable y1. Verwenden Sie dabei die vorgegebene
# Variablen m, t und x. 
m = 2.5
x = 
t = 7
y = m*x +t 

# 8. Prozentberechnung 
# Ermitteln Sie den Wert für 20% von num1 und speichern Sie das Ergebnis unter
# percentage. 

per = num1 * 0.2 

#print(per)



# Bit-Operationen

# 9. Stellen Sie sich vor, dass ein System 16 digitale Eingänge besitzt. 
# 0 bedeutet, dass der Eingang inaktiv ist und 1 aktiv. Die Eingänge sind 
# aufgeteilt in zwei achter Segmente und wie folgt durchnummeriert:
# Pin1.0, Pin1.1, Pin1.2 ... Pin1.7 und
# Pin2.0, Pin2.1, Pin2.2 ... Pin2.7
# Die Segmente 1 und 2 können damit jeweils in einem Byte beschrieben werden. 
# (Jeder Pin stellt ein Bit im Byte dar). Erstellen Sie die Variablen pin1 und 
# pin2 und weisen Sie die Werte zu, um die folgenden Eingangsaktivitäten 
# abzubilden (die restlichen Pins sind inaktiv, also 0): 
# Pin 1.4, 1.5 und 1.7  = 1
# Pin 2.2, 2.5 und 2.6  = 1

pin1 = 0b10110000
pin2 = 0b01100100

# 10. Bit-Operationen
# Nutzen Sie die Bit-Operationen (&, |, ^, ~, <<, >>) mit den Variablen pin1 
# sowie pin2 und speichern Sie das Ergebnis in der jeweiligen Variable. 
# Im Falle der Bit-Shifts, verschieben Sie nur um eine Position. 
result_and = pin1 & pin2
#result_or = 
# result_xor
# result_not_pin1
# result_not_pin2
# result_not_pin1_lshift
# result_not_pin1_rshift
# Veranschaulichen Sie sich das jeweilige Ergebnis mit einer print-Anweisung. 
# Entsprechen die Ergebnisse Ihren Erwartungen? 

print(f"{bin(pin1)} AND {bin(pin2)} => {bin(result_and)} / {hex(result_and)}")

# 11. Prüfung Aktivität eines Pins
# Nutzen Sie das Wissen der vorherigen Aufagbe, um zu prüfen, ob der Pin2.4 
# aktiv ist. Speichern Sie das Ergebnis in der Variable pin2_4_activity
# Hinweis: Verwenden Sie eine sogeannte Bit-Maske


# 12. Prüfung der Aktivität von 2 bestimmten Pins
# Nutzen Sie Bit-Masken, und speichern Sie das Ergebnis, ob der Pin1.5 oder 
# Pin2.2 gesetzt ist, in die Variable pin_activity. Dafür benötigt es nur eine
# Code-Zeile.


# 13. Bit-Shft
# Die Aufgabe 12 lässt sich auch duch 2 Bit-Shifts lösen. Speichern Sie das 
# Ergebnis unter der Variable pin_activity_2. Dafür benötigt es nur eine
# Code-Zeile


# 14: Vergleich
# Vergleichen Sie die Werte von Variable num1 und num2 und setzen Sie ent-
# sprechend die Variable state wie folgt: 
# state = 0 für num1 größer als num2
# state = 1 für num1 kleiner als num2 
# state = 5 für num1 gleich num1