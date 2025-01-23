# Sypher
Dokumentacja:

Pliki:
newProject.py - Plik główny szyfrujący i deszyfrujący, nakłada również ochronę przed atakiem
bruteForce.py - Plik atakujący metodą brute force attack (sprawdza wszystkie kombinacje chasła, chasło ograniczone do 2 znaków ze względu na czas)
file_for_python - plik który jest szyfrowany 
encrypted_file - plik zaszyfrowany
decrypted_file - plik odszyfrowany za pomocą pliku bruteForcy.py

Opis działania:
newProject.py pierw pyta się czy nadać ochronę która zwiększa liczbę iteracji w PBKDF2, szyfruje plik file_for_python a potem go odszyfrowuje i wysyła pliki na podaną ścieżkę.

bruteForce.py wykorzystuję metodę brute force atak czyli odgadnięcie chasła za pomocą sprawdzenia wszystkich możliwych kombinacji chasła. Jeśli nie została nałożona ochrona plik ten wyświetli ustawione chasło w pliku newProject.py oraz odszyfruje i wyświetli plik tekstowy.


Opis algorytmów:
PBKDF2 (Password-Based Key Derivation Function 2)
Zastosowanie: Wykorzystywany do generowania klucza kryptograficznego z hasła użytkownika i losowego salt.
Co robi: Proces iteracyjny: PBKDF2 wykonuje wielokrotne (100 000 lub 500 000) przekształcenia hasła, co zwiększa trudność ataku brute force.

AES (Advanced Encryption Standard)
Zastosowanie: Algorytm szyfrowania symetrycznego do zabezpieczenia danych.
Co robi: W każdym bloku danych szyfrowanych wykorzystywany jest wynik szyfrowania poprzedniego bloku. Dzięki temu ten sam tekst jawny nigdy nie da tego samego szyfrogramu.


PKCS7 Padding
Zastosowanie: Wypełnianie (padding) tekstu jawnego przed szyfrowaniem. AES wymaga, aby dane wejściowe miały rozmiar będący wielokrotnością rozmiaru bloku (128 bitów).
Co robi: Dodaje niezbędne bajty, aby dane miały odpowiednią długość, a po deszyfrowaniu padding jest usuwany.


