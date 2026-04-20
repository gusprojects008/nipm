Melhorias futuras e possíveis funcionalidades:
Adicionar macanismo de history para auto-complete de comandos, como "create-profile" etc...
Melhorar logs e colorir eles.
Incluindo o modo delas).

O usuário poderá definir a metric (prioridade de interface) através da própria interface, movendo a interface para topo.

Funcionalidades:
O usuário poderá editar, excluir ou criar os arquivos de configurações de interfaces, através da TUI.
Definir modos de interface diretamente pela TUI.
Em interfaces station, o usuário poderá fazer scan por redes wifi, se conectar a uma rede, e adicionar a rede que ele se conectou, no arquivo wpa_supplicant relacionado à interface conectada, em seguida, irá abrir o arquivo wpa_supplicant da interface, para ele definir qual rede é possui mais prioridade para o wpa_supplicant.
Ele poderá ativar ou desativar interfaces, definir modos, prioridades etc...
Editar configurações de arquivo dhcpcd para cada interface.
O usuário poderá ativar o modo AP, nesse momento irá ser aberto o arquivo de configuração do hostapd para ele editar.

Algumas lógicas de funcionamento que pensei:
Para fornecer a possibilidade do usuário editar arquivos de configurações pela TUI, provalmente irei utiliza o mesmo método que o mitmproxy utiliza.
O usuário não precisará executar todo o programa como sudo, pois como o programa atualmente baseia-se em funcionalidades que executam subprocessos, posso fazer com que o usuário digite a senha antes de executar um comando para alterar o modo da interface por exemplo, ou para para o serviço do wpa_supplicant ou dhcpcd. 
O usuário poderá desativar o processo do wpa_supplicant ou dhcpcd diretamente pela TUI. Mas como vou fazer isso sem conhecer diretamente qual gerenciador de serviço ele utiliza.
Provavelmente irei ter que implementar aquele mecanismo ("watching" se não me engano) que aguarda o evento de edição de arquivos de configuração dentro do NIPM. Para assim, ler eles novamente e inciar o loop de gerenciamento de interfaces.
Toda vez que os arquivos wpa_supplicant forem editado e carregados, irei ter que parsear eles, obter PSK e os dados necessários para gerar a psk hexadecimal novamente, a partir da entrada de configuração da rede específica relacionada à interface específica. Isso serve para evitar com que o usuário acidentalemente tenha editado a psk hexadecimal usada no arquivo wpa_supplicant, e assim, fazer com que ele se preucupe apenas apenas com a psk normal da rede.

Futuramente quero estender para ter funcionalidades como:
Gerenciar bluetooth.
Modo avião (desativa todas as interfaces).
Ancoragem bluetooth, Ancoragem USB e Ancoragem Ethernet, VPN, DNS Privado, Busca de aparelhos de próximos.
Channel hopper na interface monitor. Mas faz sentido o usuário poder simplesmente configurar channel hopping em uma interface monitor, mas aplicação TUI não fornece uma funcionalidade que usufrua desse channel hopping, ou seja, essa funcionalidade supõe que o usuário utiliza a interface monitor para outra finalidade com outro outro programa (um sniffer de rede), então ainda vale a pena? talvez sim, pois se parar para pensar, eu estou fornecendo a funcionalidade do usuário configurar a interface para modo monitor, mas a aplicação em si não fornece funcionalidades que usufrua dessa interface nesse modo.
Talvez facilitar o uso da aplicação, adicionando mais atalhos que evitam com que o usuário tenha que mexer nos arquivos de configuração sempre que quiserem editar algo.


O arquivo "nipm-config.json" ele é reponsável por permitir o parser criar ou atualizar os arquivos de configuração "wpa_supplicant" ou "dhcpcd" para da interface específica, a estrutura dele atualmente:
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
  },
  "wlp0s20f0u3u2": {
    "hwaddr": "0c:c6:55:2b:0c:e3",
    "type": "wireless",
    "metric": 100,
    "ssid": "LOARA",
    "psk": "10194450",
    "psk_hex": "fop60ea28309d6d1e1d9a28178d1aa2db7cc68f458e8a7525d6f6780b68fda99",
    "wpa_supplicant_conf_path": "/home/gus/.config/nipm/wpa-supplicant-wlp0s20f0u3u2.conf",
    "dhcpcd_conf_path": "/home/gus/.config/nipm/dhcpcd-wlp0s20f0u3u2.conf"
  },
  "enp0s20f0u3u1": {
    "hwaddr": "de:b1:10:d5:0e:d7",
    "type": "ethernet",
    "metric": 50,
    "dhcpcd_conf_path": "/home/gus/.config/nipm/dhcpcd-enp0s20f0u3u1.conf"
  },
  "enp0s20f0u3": {
    "hwaddr": "2a:29:ea:fb:3b:24",
    "type": "ethernet",
    "metric": 10,
    "dhcpcd_conf_path": "/home/gus/.config/nipm/dhcpcd-enp0s20f0u3.conf"
  }
}

A nova estrutura que pensei:
{
  "wlp0s20f0u3": {
    "hwaddr": "0c:c6:55:2b:0c:e3",
    "type": "wireless",
    "metric": 20,
    "profiles": {
        "station":
            "um número ou nome específico que o usuário quis definir": {
                "wpa_supplicant": {
                    "LOPES": {
                        "psk": "10110443",
                        "psk_hex": "fdc60ea28309d6d1e1d9a28178d1aa2db7cc68f458r8a7565d6f6780b68fda99",
                        "path": "/home/gus/.config/nipm/wpa-supplicant-wlp0s20f0u3.conf",
                    }
                },
                "dhcpcd": {
                    "path": "/home/gus/.config/nipm/dhcpcd-wlp0s20f0u3.conf"
                }
            },
        },
    },
  },
  ""
  "enp0s20f0u3u1": {
    "hwaddr": "de:b1:10:d5:0e:d7",
    "type": "ethernet",
    "metric": 50,
    "dhcpcd": {
        "path": "/home/gus/.config/nipm/dhcpcd-enp0s20f0u3u1.conf"
    }
  },
}

Acho que a estrutura de entrada de cada interface irá ter que depender do tipo dela.

Algumas dúvidas que tenho atualmente:
Será que é melhor ter o "hwaddr" como key principal para a entrada da interface? do que ter o nome dela como chave? se "hwaddr" for melhor (o que suspeito que é) então é só começar a gerar o arquivo nipm-config.json utilizando hwaddr como key para entrada das interfaces.
Vou ter que aplicar mecanismo de metric para profiles? e para as entradas dentro do dict de wpa_supplicant?

Interface TUI:

