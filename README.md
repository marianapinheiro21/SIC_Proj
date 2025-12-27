# Projeto SIC: Rede Ad-hoc Segura baseada em Bluetooth

## Identificação do Grupo
* **Autor 1**: Arthur Melo (102667) - Contribuição: 25%
* **Autor 2**: [Nome] ([Número]) - Contribuição: 25%
* **Autor 3**: [Nome] ([Número]) - Contribuição: 25%
* **Autor 4**: [Nome] ([Número]) - Contribuição: 25%

---

## 1. Estrutura do Projeto
O projeto está organizado em 4 pastas principais:

* **`/sync`**: Contém o código exclusivo do Sink, responsável pelo serviço de *heartbeat* e pelo serviço *Inbox*.
* **`/node`**: Contém o código dos nós IoT, incluindo o *daemon* de encaminhamento e gestão de *uplinks*.
* **`/common`**: Código partilhado, incluindo a lógica de pacotes, criptografia e protocolos de autenticação mútua.
* **`/support`**: Ferramentas de suporte, como a Autoridade Certificadora (CA) e o emissor de certificados X.509.

---

## 2. Design e Implementação

### Topologia e Encaminhamento
  A rede organiza-se numa **topologia em árvore**. Cada nó escolhe um *uplink* com base no menor número de saltos (*hop count*) até ao Sink. 
*  **Heartbeat**: O Sink emite um sinal a cada 5 segundos. A perda de 3 mensagens consecutivas indica falha no link.
* **Addressing**: Utilizamos **NIDs de 128 bits** gerados no provisionamento. O encaminhamento é feito através de tabelas de *forwarding* que memorizam o caminho de volta para cada NID.



### Segurança
A segurança é implementada em dois níveis:

1.  **Segurança por Link (Per-link)**:
    * **Pareamento**: Usamos Bluetooth "Just Works" apenas para a conexão inicial.
    * **Autenticação Mútua**: Após a conexão, os nós trocam certificados X.509 (Curva P-521) e realizam uma prova de posse através da assinatura de um *nonce*[cite: 81, 93].
    *  **Integridade**: Todas as mensagens entre vizinhos incluem um **MAC** para garantir integridade e evitar ataques de *replay*.

2.  **Segurança de Ponta-a-Ponta (End-to-End)**:
    * **DTLS**: A comunicação entre cada nó e o serviço *Inbox* no Sink é protegida por **DTLS**.
    * **Encaminhamento Transparente**: Os nós intermédios encaminham o tráfego sem aceder ao conteúdo cifrado pelo DTLS.



---

## 3. Funcionalidades Implementadas
| Tarefa de Implementação | Estado | Descrição |
| :--- | :---: | :--- |
| **Mecanismos Base BLE** | [] | Criação e destruição de ligações Bluetooth entre dispositivos IoT. |
| **Controlos de Rede** | [] | Interface para procura de dispositivos, visualização de hops e simulação de quebra de links. |
| **Gestão de Certificados** | [] | Criação de certificados P-521 via CA e negociação de chaves de sessão para links Bluetooth. |
| **Encaminhamento Base** | [] | Routing via NIDs (128-bit), identificação de serviços/clientes e uso de MAC para integridade/freshness. |
| **Broadcast Downlink** | [] | Mecanismo de inundação (flooding) para suporte ao protocolo de *heartbeat*. |
| **Deteção de Falhas** | [] | Implementação de *timeouts* no *heartbeat* para identificar e reagir a falhas de uplink. |
| **Serviço Inbox** | [] | Implementação do serviço de receção de mensagens arbitrárias no Sink e nos nós. |
| **Segurança DTLS** | [] | Adição de proteção DTLS ao serviço de encaminhamento de mensagens (End-to-End). |

## 4. Instruções de Execução
1.  Gerar certificados na pasta `/support`.
2.  Lançar o Sink na pasta `/sync`.
3.  Lançar os nós na pasta `/node` (requer `simpleBLE` e adaptadores Bluetooth ativos).