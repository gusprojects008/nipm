## Ideias e implementações futuras
Esta seção contém percepções coletadas durante o desenvolvimento; nenhuma está garantida para ser implementada. Elas exigem revisão e pesquisa adicional.

---

## O que está faltando? para corrigir / adicionar

* Finalizar estrutura definitiva do `nipm-config.json`.
* Definir arquitetura final da TUI.
* Possíveis problemas relacionados à remoção de um socket wpa_supplicant a partir de um path arbitrário que pode mudar de acordo com algumas distrubuições linux `/var/run/wpa_supplicant/ifname`.

---

## Local para anotar as melhorias e correções durante o projeto (pode ser utilizado no release)

* Command and interface auto-complete.
* Improved architecture, greater scalability, detailed explanation in cli-core/templates/python.

---

## Padrões do projeto que é aconselhavel/recomendável serem seguidos

* Todas as funções que a TUI fornecer, a CLI também irá fornecer.
* Priorizar compatibilidade com diferentes ambientes Linux.
* Evitar dependência forte de um init system específico.

---

## Explicações e esclarecimentos

* O objetivo do `nipm-config.json` é servir como base para geração e atualização dos arquivos de configuração relacionados às interfaces.
* O projeto não pretende depender exclusivamente de um gerenciador de serviços específico.
* Algumas funcionalidades podem depender de permissões elevadas apenas durante ações específicas.

---

## Decisões de arquitetura pendentes:

* Utilizar nome da interface ou `hwaddr` como chave principal.

---

## TUI

### Estrutura atual do `nipm-config.json`

```json
{
  "wlp0s20f0u3": {
    "hwaddr": "0c:c6:55:2b:0c:e3",
    "type": "wireless",
    "metric": 20,
    "ssid": "LOPES",
    "psk": "10110443",
    "psk_hex": "fdc60ea28309d6d1e1d9a28178d1aa2db7cc68f458r8a7565d6f6780b68fda99",
    "wpa_supplicant_conf_path": "/home/gus/.config/nipm/wpa-supplicant-wlp0s20f0u3.conf",
    "dhcpcd_conf_path": "/home/gus/.config/nipm/dhcpcd-wlp0s20f0u3.conf"
  }
}
```

### Estrutura nova planejada

```json
{
  "wlp0s20f0u3": {
    "hwaddr": "0c:c6:55:2b:0c:e3",
    "type": "wireless",
    "metric": 20,
    "profiles": {
      "station": {
        "default": {
          "wpa_supplicant": {
            "LOPES": {
              "psk": "10110443",
              "psk_hex": "fdc60ea28309d6d1e1d9a28178d1aa2db7cc68f458r8a7565d6f6780b68fda99",
              "path": "/home/gus/.config/nipm/wpa-supplicant-wlp0s20f0u3.conf"
            }
          },
          "dhcpcd": {
            "path": "/home/gus/.config/nipm/dhcpcd-wlp0s20f0u3.conf"
          }
        }
      }
    }
  }
}
```

### Funcionalidades planejadas
* Gerenciamento de bluetooth.
* Modo avião para desativar todas as interfaces.
* Ancoragem bluetooth, USB e Ethernet.
* Suporte a VPN e DNS privado.
* Busca de dispositivos próximos.
* Channel hopping para interfaces monitor.
* Melhorar gerenciamento de profiles por interface.
* Avaliar uso de métricas (`metric`) em profiles e entradas `wpa_supplicant`.
* O usuário poderá editar configurações diretamente pela TUI.
* Permitir gerenciamento de serviços diretamente pela TUI.
* Adicionar mais atalhos na TUI para reduzir edição manual de arquivos.
* Editar, excluir e criar arquivos de configuração pela TUI.
* Alterar modos de interface diretamente pela TUI.
* Fazer scan de redes Wi-Fi.
* Conectar em redes wireless.
* Gerenciar prioridade de redes no wpa_supplicant.
* Ativar e desativar interfaces.
* Editar configurações específicas do dhcpcd.
* Ativar modo AP.
* Gerenciar serviços relacionados à rede diretamente pela TUI.

### Detalhes de funcionamento técnico
* A PSK hexadecimal pode ser regenerada automaticamente para evitar inconsistências.
* Abrir automaticamente configuração do hostapd ao ativar AP.
* A edição de arquivos pela TUI pode utilizar abordagem semelhante ao mitmproxy.
* O usuário não precisará executar toda a aplicação como root.
* Apenas ações específicas exigirão senha ou privilégios elevados.
* O sistema poderá observar alterações em arquivos de configuração para recarregar estados automaticamente.
* O parser poderá regenerar automaticamente PSKs hexadecimais.
* O usuário deverá se preocupar apenas com a PSK normal da rede.
* Implementar mecanismo de watch para detectar alterações em arquivos de configuração.
