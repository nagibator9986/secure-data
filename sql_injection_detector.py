import requests,sys,time

from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint

s = requests.Session()



try:
	def slowprint(s):
		for c in s + '\n' :
			sys.stdout.write(c)
			sys.stdout.flush()
			time.sleep(10. / 100)
			
	def get_all_forms(url):
		"""Для `url` он возвращает все формы из содержимого HTML"""
		soup = bs(s.get(url).content, "html.parser")
		return soup.find_all("form")


	def get_form_details(form):
		"""
		Эта функция извлекает всю возможную полезную информацию о HTML-форме.
		"""
		details = {}
		# получить действие формы (целевой URL)
		try:
			action = form.attrs.get("action").lower()
		except:
			action = None
		# получить метод формы (POST, GET и т.д.)
		method = form.attrs.get("method", "get").lower()
		# получить все данные ввода, такие как тип и имя
		inputs = []
		for input_tag in form.find_all("input"):
			input_type = input_tag.attrs.get("type", "text")
			input_name = input_tag.attrs.get("name")
			input_value = input_tag.attrs.get("value", "")
			inputs.append({"type": input_type, "name": input_name, "value": input_value})
		# помещаем все в полученный словарь
		details["action"] = action
		details["method"] = method
		details["inputs"] = inputs
		return details


	def is_vulnerable(response):
		"""Простая логическая функция, определяющая, является ли страница
уязвима ли SQL-инъекция из-за ее `ответа`"""
		
		for error in errors:
			# если вы найдете одну из этих ошибок, верните True
			if error in response.content.decode().lower():
				return True
		# no error detected
		return False


	def scan_sql_injection(url):
		# проверка URL
		for c in "\"'":
			# добавить символ кавычки/двойной кавычки к URL
			new_url = f"{url}{c}"
			print("\033[93m [!] Trying", new_url)
			# сделать HTTP-запрос
			res = s.get(new_url)
			if is_vulnerable(res):
				# SQL-инъекция обнаружена на самом URL,
				# нет необходимости предварительно извлекать формы и отправлять их
				print("\033[92m [+] SQL Injection vulnerability detected, link:", new_url)
				return
		# тест на HTML-формах
		forms = get_all_forms(url)
		slowprint(f"\033[92m [+] Detected {len(forms)} forms on {url}.")
		for form in forms:
			form_details = get_form_details(form)
			for c in "\"'":
			# тело данных, которое мы хотим отправить
				data = {}
				for input_tag in form_details["inputs"]:
					if input_tag["value"] or input_tag["type"] == "hidden":
					# любая форма ввода, которая имеет некоторое значение или скрыта,
					# просто используйте его в теле формы		
						try:
							data[input_tag["name"]] = input_tag["value"] + c
						except:
							pass
					elif input_tag["type"] != "submit":
						# все остальные, кроме отправки, использовать некоторые ненужные данные со специальными символами
						data[input_tag["name"]] = f"test{c}"
				# соедините URL-адрес с действием (URL-адрес запроса формы)
				url = urljoin(url, form_details["action"])
				if form_details["method"] == "post":
					res = s.post(url, data=data)
				elif form_details["method"] == "get":
					res = s.get(url, params=data)
				# проверить, уязвима ли результирующая страница
				if is_vulnerable(res):
					slowprint("\033[92m [+] SQL Injection vulnerability detected, link:", url)
					slowprint("\033[92m [+] Form:")
					pprint(form_details)
					break   

	if __name__ == "__main__":
		import sys
		url = sys.argv[1]
		scan_sql_injection(url)
except KeyboardInterrupt:
	slowprint("\n\033[91m [-] Exiting...")
