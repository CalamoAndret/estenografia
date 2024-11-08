# Importação das bibliotecas necessárias
from PIL import Image
import stepic
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# Função para gerar o par de chaves pública e privada
def gerar_chaves():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Salvar as chaves em arquivos
    with open("chave_privada.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open("chave_publica.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("Par de chaves gerado e salvo em 'chave_privada.pem' e 'chave_publica.pem'.")
    return private_key, public_key

# Funções de criptografia e descriptografia
def encriptar_mensagem(mensagem, public_key):
    mensagem_encriptada = public_key.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensagem_encriptada

def descriptografar_mensagem(mensagem_encriptada, private_key):
    mensagem_decriptada = private_key.decrypt(
        mensagem_encriptada,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return mensagem_decriptada.decode()

# Funções de esteganografia
def embutir_texto_em_imagem():
    caminho_imagem = input("Digite o caminho da imagem (Exemplo: 'imagem.png'): ")
    imagem = Image.open(caminho_imagem)
    mensagem = input("Digite o texto que deseja embutir na imagem: ").encode()
    imagem_esteganografada = stepic.encode(imagem, mensagem)
    caminho_saida = input("Digite o caminho de saída para a imagem (Exemplo: 'imagem_saida.png'): ")
    imagem_esteganografada.save(caminho_saida)
    print(f"Texto embutido com sucesso em '{caminho_saida}'.")

def recuperar_texto_de_imagem():
    caminho_imagem = input("Digite o caminho da imagem com o texto embutido (Exemplo: 'imagem_saida.png'): ")
    imagem = Image.open(caminho_imagem)
    try:
        mensagem = stepic.decode(imagem)
        print("Texto recuperado:", mensagem)
        return mensagem
    except Exception as e:
        print("Nenhuma mensagem foi encontrada ou houve um erro:", str(e))
        return None

# Funções de hashing e comparação
def gerar_hash(imagem):
    hash_obj = hashlib.sha256()
    hash_obj.update(imagem.tobytes())
    return hash_obj.hexdigest()

def comparar_hash_imagens():
    caminho_imagem_original = input("Digite o caminho da imagem original (Exemplo: 'imagem.png'): ")
    imagem_original = Image.open(caminho_imagem_original)
    caminho_imagem_alterada = input("Digite o caminho da imagem alterada com steganography (Exemplo: 'imagem_saida.png'): ")
    imagem_alterada = Image.open(caminho_imagem_alterada)
    hash_original = gerar_hash(imagem_original)
    hash_alterada = gerar_hash(imagem_alterada)
    print("\nHash da imagem original:", hash_original)
    print("Hash da imagem alterada:", hash_alterada)
    if hash_original != hash_alterada:
        print("\nAs imagens são diferentes: a esteganografia alterou os pixels da imagem.")
    else:
        print("\nAs imagens são idênticas: não houve alteração perceptível nos pixels.")

# Funções para encriptar, embutir e descriptografar
def encriptar_e_embutir_mensagem():
    private_key, public_key = gerar_chaves()
    mensagem = input("Digite a mensagem que deseja encriptar e embutir na imagem: ")
    mensagem_encriptada = encriptar_mensagem(mensagem, public_key)
    print("Mensagem encriptada com sucesso.")
    caminho_imagem = input("Digite o caminho da imagem para embutir o texto encriptado (Exemplo: 'imagem.png'): ")
    imagem = Image.open(caminho_imagem)
    imagem_esteganografada = stepic.encode(imagem, mensagem_encriptada)
    caminho_saida = input("Digite o caminho de saída para a imagem (Exemplo: 'imagem_saida.png'): ")
    imagem_esteganografada.save(caminho_saida)
    print(f"Mensagem encriptada e embutida com sucesso em '{caminho_saida}'.")

def descriptografar_texto_de_imagem():
    mensagem_encriptada = recuperar_texto_de_imagem()
    try:
        with open("chave_privada.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        if mensagem_encriptada:
            mensagem_decriptada = descriptografar_mensagem(mensagem_encriptada, private_key)
            print("Texto descriptografado:", mensagem_decriptada)
        else:
            print("Nenhuma mensagem encriptada foi encontrada na imagem.")
    except Exception as e:
        print("Erro ao descriptografar a mensagem:", str(e))

# Menu principal
def main():
    while True:
        print("\nMenu de Opções:")
        print("1 - Embutir texto em uma imagem")
        print("2 - Recuperar texto de uma imagem")
        print("3 - Gerar hash das imagens original e alterada")
        print("4 - Encriptar mensagem com chave pública e embutir na imagem")
        print("5 - Descriptografar texto encriptado de uma imagem")
        print("S - Sair")
        
        opcao = input("Escolha uma opção: ").strip().upper()
        
        if opcao == "1":
            embutir_texto_em_imagem()
        elif opcao == "2":
            recuperar_texto_de_imagem()
        elif opcao == "3":
            comparar_hash_imagens()
        elif opcao == "4":
            encriptar_e_embutir_mensagem()
        elif opcao == "5":
            descriptografar_texto_de_imagem()
        elif opcao == "S":
            print("Saindo...")
            break
        else:
            print("Opção inválida! Tente novamente.")

# Executa o menu
if __name__ == "__main__":
    main()
