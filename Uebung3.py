alter = 25
groesse = 1.83

#Ausgabe, welcher Typ jede Variable hat.

    #print(type(alter))
    #print(type(groesse))

#<class 'int'>
#<class 'float'>

a1 = 55
a2 = 54

summe = (a1+a2)
diff = (a1-a2)
prod = (a1*a2)
quot = (a1/a2)
rest_div =(a1%a2)
ganzzdiv = (a1//a2)
potnz = (a1**a2)

#print(summe, diff, prod, quot, rest_div, ganzzdiv, potnz)

#if a1 > a2:
  #  print(f"{a1} ist größer als {a2}") 

#elif a1 == a2:
 #   print(f"{a1} ist gleich {a2}") 

#else:
 #   print(f"{a1} ist kleiner als  {a2}")
    
    # normale If-schleife 


#jetzt das ganze mit Input, also dass variablen a1 und a2 per Tastaur eingegeben werden. 

#a3 = int(input("Eingabe Zahl 1:"))
#a4 = int(input("EIngabe Zahl 2:"))



#if a3 > a4:
   # print(f"{a3} ist größer als {a4}") 

#elif a3 == a4:
   # print(f"{a3} ist gleich {a4}") 

#else:
   # print(f"{a3} ist kleiner als  {a4}")
    


#x = 0
#while x > -1:
   # print(x)

  #  x = x+1





#jezt mit WHileschleife

#a3 = int(input("Eingabe Zahl 1:"))
#a4 = int(input("EIngabe Zahl 2:"))


# while True:

#     if a3 > a4:
#         print(f"{a3} ist größer als {a4}") 

#     elif a3 == a4:
#         print(f"{a3} ist gleich {a4}") 

#     else:
#         print(f"{a3} ist kleiner als  {a4}")

#     beenden = input("Wiederholen? (J/N)")
#     if beenden.lower()!= "j":
#         break  
    

    
    
    


# while True:

#     a3 = int(input("Eingabe Zahl 1:"))
#     a4 = int(input("EIngabe Zahl 2:"))

#     if a3 > a4:
#         print(f"{a3} ist größer als {a4}") 

#     elif a3 == a4:
#         print(f"{a3} ist gleich {a4}") 

#     else:
#         print(f"{a3} ist kleiner als  {a4}")

#     beenden = input("Wiederholen? (J/N)")
#     if beenden.lower()!= "j":
#         break 
    

import random

print("Errate eine Zahl zwischen 1 und 20, du hast 5 Versuche!")
while True:
    
    zufallszahl = random.randint(1,20)
    for i in range (5):
     #print(f"{zufallszahl}")
     eingabe = int(input("Wähle eine Zahl:"))
     if eingabe.isdigit():
          zahl1 = eingabe
    else: 
         print("ZWISCHEN 1 UND 20!!!!")
        
         if zahl1 > 20 or zahl1 < 1:  #zahl1 > 20 or zahl1 < 1 funktioniert nur mit Zahlen Buchstaben würden das programm crashen
               print ("versuche es nochmal")

         elif zahl1 == zufallszahl:
               print("Congratulation!!! correct number")
               break

         else:
               if zahl1 < zufallszahl: # If schleife um Höher oder niedriger zu bestimmen. 
                  
                     print(f"Höher! \n Try again du hast noch {4 - i} Versuche!")

               else:
               
               
                     print(f"Niedriger! \n Try again du hast noch {4 - i} Versuche!")

    beenden = input("Nochmal spielen? (J/N)")
    if beenden.lower() !="j":
        break

