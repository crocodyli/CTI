import requests
import json
import time

def consultar_virustotal(hash):
    # Insira sua chave de API do VirusTotal aqui
    api_key = 'XXXXX'

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


# Loop principal
try:
    while True:
        print('''
██╗   ██╗████████╗███████╗███████╗ █████╗ ██████╗  ██████╗██╗  ██╗
██║   ██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║
██║   ██║   ██║   ███████╗█████╗  ███████║██████╔╝██║     ███████║
╚██╗ ██╔╝   ██║   ╚════██║██╔══╝  ██╔══██║██╔══██╗██║     ██╔══██║
 ╚████╔╝    ██║   ███████║███████╗██║  ██║██║  ██║╚██████╗██║  ██║
  ╚═══╝     ╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
                                                                  
     Created by: @caiquebarqueta (LinkedIn) @crocodylii (Twitter)                                                                         
    ''')
        hashes = input('Insira as hashes separadas por vírgula (MD5, SHA1 ou SHA256) [ou "sair" para encerrar]: ')
        if hashes.lower() == 'sair':
            break

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

        # Salvar a saída em um arquivo
        extensao = input("Digite a extensão do arquivo (txt ou json): ")

        if extensao == "txt":
            nome_arquivo = input("Digite o nome do arquivo: ") + ".txt"
            with open(nome_arquivo, "w") as arquivo:
                for result in results:
                    arquivo.write(f"Hash: {result['hash']}\n")
                    arquivo.write(f"{result['score']}\n")
                    arquivo.write("Detalhes adicionais:\n")
                    for key, value in result['details'].items():
                        arquivo.write(f"{key}: {value}\n")
                    arquivo.write("\n")
            print("Arquivo salvocom sucesso!")
        elif extensao == "json":
            nome_arquivo = input("Digite o nome do arquivo: ") + ".json"
            with open(nome_arquivo, "w") as arquivo:
                json.dump(results, arquivo, indent=4)
            print("Arquivo salvo com sucesso!")
        else:
            print("Extensão de arquivo inválida. O arquivo não foi salvo.")

    print('Programa encerrado.')
    input("Pressione Enter para sair...")
except KeyboardInterrupt:
    print('Programa encerrado.')
