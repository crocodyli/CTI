import requests
import json
import time
import argparse
from pathlib import Path

def consultar_virustotal(hash):
    url = f'https://www.virustotal.com/api/v3/files/{hash}'
    headers = {
        'x-apikey': api_key
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json_response = response.json()
        if 'data' in json_response and 'attributes' in json_response['data']:
            attributes = json_response['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                malicious_count = stats['malicious']
                undetected_count = stats['undetected']
                score = f"Score malicioso: {malicious_count}/{malicious_count + undetected_count}"
                print(score)

                # Exibir detalhes adicionais específicos
                print("Detalhes adicionais:")
                desired_fields = ['sha256', 'sha1', 'md5', 'type_description', 'tlsh', 'vhash',
                                  'tags', 'type_extension', 'type_tags', 'creation_date',
                                  'popular_threat_classification', 'magic', 'meaningful_name']
                details = {}
                for field in desired_fields:
                    if field in attributes:
                        details[field] = attributes[field]
                        print(f"{field}: {attributes[field]}")

                return score, details
            else:
                print('Nenhuma informação disponível para o hash.')
        else:
            print('Nenhuma informação disponível para o hash.')
    else:
        print('Erro ao fazer a consulta.')

def write_file(filename, ext, results):
    if ext == "json":
        with open(filename, "w") as arquivo:
            json.dump(results, arquivo, indent=4)
        print("Arquivo salvo com sucesso!")
        return
    
    with open(filename, "w") as arquivo:
        for result in results:
            arquivo.write(f"Hash: {result['hash']}\n")
            arquivo.write(f"{result['score']}\n")
            arquivo.write("Detalhes adicionais:\n")
            for key, value in result['details'].items():
                arquivo.write(f"{key}: {value}\n")
            arquivo.write("\n")
    print("Arquivo salvo com sucesso!")

# Loop principal
try:

    print('''
██╗   ██╗████████╗███████╗███████╗ █████╗ ██████╗  ██████╗██╗  ██╗
██║   ██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║
██║   ██║   ██║   ███████╗█████╗  ███████║██████╔╝██║     ███████║
╚██╗ ██╔╝   ██║   ╚════██║██╔══╝  ██╔══██║██╔══██╗██║     ██╔══██║
 ╚████╔╝    ██║   ███████║███████╗██║  ██║██║  ██║╚██████╗██║  ██║
  ╚═══╝     ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                  
     Created by: @caiquebarqueta (LinkedIn) @crocodylii (Twitter)                                                                         
    ''')
    
    # Insira sua chave de API do VirusTotal aqui ou utilize o comando -k na linha de comando
    api_key = 'XXXX'

    parser = argparse.ArgumentParser(description='Scan automatizado de hashs utilizando o banco de dados do virus total.')
    parser.add_argument('-f', '--file', help='fornece um arquivo de texto com hashs para serem pesquisadas, o arquivo deve conter um hash por linha.')
    parser.add_argument('-o', '--output', help='fornece um arquivo de output para salvar os resultados, arquivo deve ser .txt ou .json')
    parser.add_argument('-k', '--apikey', help='substitui a apikey salva hardcoded por a apikey fornecida')
    args = parser.parse_args()
    if args.apikey:
        api_key = args.apikey
    if args.file:
        path = Path(args.file)
        if path.exists() and path.is_file():
            file_contents = path.read_text()
            hash_list = file_contents.split('\n')
        else:
            print("arquivo invalido")
            exit()
    else:
        hashes = input('Insira as hashes separadas por vírgula (MD5, SHA1 ou SHA256) [ou "sair" para encerrar]: ')
        if hashes.lower() == 'sair':
            exit()
        hash_list = hashes.split(',')
        
    results = []
    for index, hash in enumerate(hash_list, start=1):
        result = consultar_virustotal(hash.strip())
        if result:
            score, details = result
            results.append({"hash": hash.strip(), "score": score, "details": details})
        print('\n')

        # Aguardar 1 minuto e 30 segundos a cada grupo de 4 requisições
        if index % 4 == 0 and index < len(hash_list):
            print("Aguardando 1 minuto e 30 segundos...")
            time.sleep(90)

    if args.output:
        path = Path(args.output)
        ext = path.suffix
        ext = ext.replace(".", "", -1)
        if ext != "json" and ext != "txt":
            print("Extensão de arquivo inválida. O arquivo não foi salvo.")
            exit()
        write_file(path, ext, results)
    else:
        # Salvar a saída em um arquivo
        extensao = input("Digite a extensão do arquivo (txt ou json): ")
        nome_arquivo = input("Digite o nome do arquivo: ")
        filename = nome_arquivo + "." + extensao
        if extensao != "json" and extensao != "txt":
            print("Extensão de arquivo inválida. O arquivo não foi salvo.")
            exit()
        write_file(filename, extensao, results)

    print('Programa encerrado.')
    input("Pressione Enter para sair...")
except KeyboardInterrupt:
    print('Programa encerrado.')
