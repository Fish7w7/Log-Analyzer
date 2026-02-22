# Log Analyzer

Uma ferramenta para analisar arquivos de log de servidores web e identificar padrões de ataque. Desenvolvida em Python, funciona tanto como CLI no terminal quanto como uma interface web local via Flask.

## Motivação

Logs de acesso têm muito mais informação do que parece à primeira vista. Um arquivo de 10 mil linhas pode esconder tentativas de brute force, varreduras automatizadas e requisições a arquivos sensíveis — mas ler isso na mão é inviável. Essa ferramenta automatiza essa leitura e apresenta o resultado de forma clara.

## O que ela detecta

- IPs com alto volume de falhas de autenticação (401/403), indicando possível brute force
- Requisições a paths sensíveis como `.env`, `.git`, `wp-login.php`, `phpmyadmin`
- User-agents de ferramentas conhecidas de ataque como Hydra, sqlmap e Nikto
- Distribuição de status HTTP (2xx, 3xx, 4xx, 5xx)
- Ranking dos IPs com mais requisições

## Estrutura do projeto

```
log-analyzer/
├── analyzer/
│   ├── __init__.py
│   ├── parser.py       — lê e transforma linhas de log em objetos
│   ├── detector.py     — aplica as regras de detecção
│   └── reporter.py     — formata a saída colorida no terminal
├── templates/
│   └── index.html      — interface web servida pelo Flask
├── sample/
│   └── generate.py     — gera um log de exemplo para testes
├── cli.py              — entrada da linha de comando
├── web.py              — servidor Flask (interface web)
└── requirements.txt
```

O ponto central é que `cli.py` e `web.py` compartilham o mesmo módulo `analyzer/`. Nada foi duplicado entre as duas interfaces.

## Requisitos

- Python 3.10 ou superior
- Flask (apenas para a interface web)

## Instalação

Clone o repositório e instale as dependências:

```bash
git clone https://github.com/seu-usuario/log-analyzer.git
cd log-analyzer
pip install -r requirements.txt
```

Se quiser usar apenas o CLI, não precisa instalar nada — o Python padrão já é suficiente.

## Uso

### Gerando um log de teste

O projeto inclui um gerador que cria um arquivo com tráfego normal e ataques simulados:

```bash
python sample/generate.py
```

Opções disponíveis:

```bash
python sample/generate.py --lines 500        # quantidade de linhas normais
python sample/generate.py --intensity 80     # brute force mais intenso
python sample/generate.py --no-attack        # apenas tráfego limpo
python sample/generate.py --seed 42          # resultado reproduzível
python sample/generate.py --out outro.log    # caminho de saída customizado
```

### CLI

```bash
python cli.py sample/access.log
```

Com opções:

```bash
python cli.py sample/access.log --threshold 15     # ajusta o limite de brute force
python cli.py sample/access.log --export saida.json
```

O `--threshold` define quantas falhas de autenticação um IP precisa acumular para ser marcado como suspeito. O padrão é 10.

### Interface web

```bash
python web.py
```

Acesse `http://localhost:5000` no navegador. A interface permite colar o conteúdo do log diretamente ou fazer upload de um arquivo, e apresenta os mesmos resultados do CLI de forma visual.

## Formato de log suportado

O analisador reconhece o formato padrão de access log do Apache e Nginx:

```
192.168.1.1 - - [21/Feb/2025:10:00:01 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/7.68.0"
```

Linhas que não seguem esse formato são ignoradas silenciosamente.

## Threat Score

Cada IP suspeito recebe uma pontuação de 0 a 100 calculada com base em três fatores: número de falhas de autenticação, quantidade de paths únicos acessados e erros de servidor gerados. É uma métrica orientativa, não um veredito definitivo.

## Tecnologias

- Python 3.10+ com `re`, `collections` e `dataclasses` da biblioteca padrão
- Flask para o servidor web
- HTML, CSS e JavaScript puro na interface (sem frameworks front-end)