# Auditoria local de sessões SSH no Kali

Este projeto nasceu da necessidade de saber quais comandos uma IA executou no meu Kali Linux por SSH, com as saídas e os códigos de saída disponíveis para consulta posterior. A primeira etapa cobre SSH; chamadas por MCP não entram nesta auditoria. A referência inicial foi o artigo [Logging All SSH Commands & Sessions on a Bastion Host](https://v-ananda-raj.medium.com/logging-all-ssh-commands-sessions-on-a-bastion-host-9a8ba0a0f9af), de V Ananda Raj. A implementação aqui foi adaptada para preservar stdout, stderr e código de saída dos comandos avulsos, além de oferecer consulta e reprodução no navegador.

## O que é gravado

- `ssh usuario@kali "comando"`: comando original, stdout, stderr, início, fim e código de saída.
- Sessões interativas: saída do terminal e arquivo de tempos do `script`, com reprodução no navegador ou por `scriptreplay`.
- Arquivos locais no Kali em `~/ssh-audit/`, privados para o usuário. Cada sessão recebe um ID próprio.
- Visualizador HTTPS na porta 8765, protegido por senha gerada durante a instalação. A lista tem busca por palavras nos comandos, metadados e saídas, paginação e navegação entre resultados filtrados.
- Na visualização de sessões interativas, o renderizador interpreta movimentos comuns do cursor, retrocessos e limpeza de linha para reconstruir comandos editados com Home. Cores e sequências ANSI são ocultadas; os arquivos originais permanecem intactos. Aplicações de tela cheia podem exigir um emulador de terminal completo para fidelidade perfeita.

Saídas redirecionadas pelo comando para arquivos não são gravadas como stdout/stderr. Em sessões interativas, stdout e stderr aparecem combinados no terminal. A transferência SFTP continua funcionando, mas seu conteúdo não é gravado. A solução não procura impedir adulteração deliberada dos registros nem faz centralização ou rotação automática. Os registros podem crescer bastante; acompanhe o espaço disponível.

## Requisitos

- Kali Linux com OpenSSH Server, NetworkManager para o exemplo de IP fixo, Python 3, `script` (util-linux), OpenSSL e systemd.
- Acesso SSH atual funcionando e permissão `sudo` no Kali.
- Um IP que pertença à interface do Kali e seja alcançável pelo navegador. Confirme no roteador que não conflita com o pool DHCP; uma reserva DHCP é a opção mais limpa para manter o endereço estável.

## Instalação em outra VM

1. Copie `ssh-audit.py`, `ssh-audit-view.py` e `install.sh` para uma pasta no novo Kali. Não copie senhas, chaves SSH, certificados privados nem os registros da VM anterior.
2. Confirme o usuário e o IP no Kali: `id -un`, `ip -br -4 addr`, `ip -4 route`. Mantenha uma sessão SSH aberta durante a instalação.
3. Se quiser um IP secundário fixo sem remover o DHCP, escolha um endereço livre e teste-o na LAN. Exemplo para `eth0` e o perfil `Wired connection 1`:

   ```bash
   sudo arping -I eth0 -c 3 192.168.0.240
   sudo ip address add 192.168.0.240/24 dev eth0
   nmcli -g ipv4.method,ipv4.addresses connection show 'Wired connection 1'
   sudo nmcli connection modify 'Wired connection 1' ipv4.method auto ipv4.addresses 192.168.0.240/24
   ```

   Ajuste interface, perfil e endereço à nova VM. Um teste ARP sem resposta não garante que o IP esteja fora do pool DHCP. Reserve o IP no roteador ou exclua-o do pool para evitar conflito futuro. Teste uma **nova** conexão SSH pelo endereço escolhido antes de continuar.

4. Na pasta dos três arquivos, instale usando o usuário e IP reais:

   ```bash
   sudo bash install.sh kali 192.168.0.240
   ```

   O instalador cria uma senha aleatória e um certificado HTTPS autoassinado, instala os scripts, inicia o visualizador e cria uma regra `Match User` com `ForceCommand` para o usuário informado. Antes de alterar o SSH, guarda um backup de `/etc/ssh/sshd_config`, valida a configuração candidata com `sshd -t` e só então recarrega o serviço. Não modifica chaves SSH existentes.

5. Leia a senha **no Kali**, sem publicá-la:

   ```bash
   sudo cat /home/kali/ssh-audit/.viewer-password
   ```

   Abra `https://IP_DO_KALI:8765/` no navegador. O usuário do login é o mesmo passado ao instalador. O certificado autoassinado causará um aviso de confiança na primeira visita. Não encaminhe a porta 8765 para a Internet.

## Testes após instalar

Em outra sessão, confirme o comando avulso e o código de saída:

```bash
ssh kali@IP_DO_KALI 'printf OUT; printf ERR >&2; exit 7'
echo "$?"  # 7
```

Abra uma sessão interativa, execute alguns comandos e saia com `exit 3`; verifique se o cliente SSH recebeu código `3`. Teste uma transferência SFTP/SCP usada nas suas automações. Confira os registros no navegador e os serviços no Kali com `systemctl status ssh ssh-audit-view.service`.

## Operação e recuperação

- A configuração do visualizador é gerada pelo instalador em `/etc/systemd/system/ssh-audit-view.service`.
- O wrapper fica em `/usr/local/bin/ssh-audit`; o visualizador em `/usr/local/bin/ssh-audit-view`.
- Os registros e materiais privados do visualizador ficam em `~/ssh-audit/`. Nunca publique `.viewer-password`, `.viewer-key.pem`, `.viewer-cert.pem` ou os registros.
- O backup do SSH fica em `/etc/ssh/sshd_config.pre-audit.DATA`. Se precisar desfazer, restaure o backup apropriado, execute `sudo sshd -t` e só então `sudo systemctl reload ssh`.
- Para reprodução no terminal: `scriptreplay --timing ~/ssh-audit/ID.timing --typescript ~/ssh-audit/ID.terminal`.

## Estado da VM original

Na VM usada no desenvolvimento, o usuário é `kali`, a interface `eth0` recebe DHCP e também tem `192.168.0.240/24`. A versão observada foi Kali 2026.3, com `script` do util-linux 2.42.2; `asciinema` não foi necessário. O SSH e o visualizador foram testados, inclusive stdout/stderr separados, códigos de saída, SCP, busca e reprodução. Esses valores são exemplos da VM original, não pressupostos para uma nova instalação.

## Histórico de mudanças

- **2026-11-08:** Publicação inicial do wrapper SSH, instalador e visualizador HTTPS local.
- **2026-11-08:** Busca nas sessões e saídas, paginação de 50 a 1000 entradas e navegação entre resultados filtrados.
- **2026-11-08:** Melhorias na leitura de sessões interativas: remoção de controles visíveis, preservação da saída após retornos de carro e reconstrução de comandos editados com movimentos do cursor.

As mudanças futuras serão acrescentadas aqui enquanto o projeto permanecer pequeno. O histórico completo de código está nos commits e PRs do GitHub.
