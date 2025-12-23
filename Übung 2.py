# Aufgabe 4:
# Erstelle ein Programm, das Temperaturen zwischen Celsius, Fahrenheit und 
# Kelvin umrechnen kann. Implementiere dazu verschiedene Funktionen:

# - Schreibe die Funktion celsius_to_fahrenheit(celsius), die eine Temperatur 
#   von Celsius in Fahrenheit umrechnet
# - Schreibe die Funktion fahrenheit_to_celsius(fahrenheit), die eine 
#   Temperatur von Fahrenheit in Celsius umrechnet
# - Schreibe die Funktion celsius_to_kelvin(celsius), die eine Temperatur von 
#   Celsius in Kelvin umrechnet
# - Schreibe ediene Funktion kelvin_to_celsius(kelvin), die eine Temperatur von 
#   Kelvin in Celsius umrechnet
# - Schreibe eine Hauptfunktion main(), die den Benutzer nach der gewünschten 
#   Umrechnung fragt und das Ergebnis ausgibt. Nutze dazu die Funktion input()

def celsius_to_fahrenheit (celsius):
    return celsius*1.8 + 32
   

    
def fahrenheit_to_celsius(fahrenheit): # neue Funktion Phyton zum merken augegben, Den Namen:fahrenheit_to_celsius gegeben, Zahl soll den namen fahrenheit bekommen.
    return (fahrenheit-32)*5/9
   



def celsius_to_kelvin(celsius):
    return celsius + 273.15




def kelvin_to_celsius(kelvin):
    return kelvin-273.15
    


def main():

    
    
    print("Hi, Wähle eine Zahl für:\n 1:C to F \n 2:F to C\n 3:C to K\n 4:K to C")



