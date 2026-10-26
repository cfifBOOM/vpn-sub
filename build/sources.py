"""Источники: открытые GitHub-репозитории с бесплатными конфигами под РФ.

Формат: (владелец/репозиторий, путь к файлу, метка)
  BL  — для обычного режима блокировок («чёрные списки», ЧС)
  WL  — собраны/проверены для режима белых списков на мобильном (БС)
  MIX — смешанные подборки: метку БС/ЧС сборщик ставит сам по IP-диапазонам и SNI
Порядок важен: при дублях остаётся запись из источника, указанного выше.
Чтобы добавить источник — допишите строку; чтобы убрать — удалите.
"""

TESTED_IN_RU = {"igareck"}  # владельцы, которые проверяют сервера изнутри России

SOURCES = [
    # igareck — проверка прямо из России
    ("igareck/vpn-configs-for-russia", "BLACK_VLESS_RUS.txt", "BL"),
    ("igareck/vpn-configs-for-russia", "BLACK_VLESS_RUS_mobile.txt", "BL"),
    ("igareck/vpn-configs-for-russia", "BLACK_SS+All_RUS.txt", "BL"),
    ("igareck/vpn-configs-for-russia", "BLACK_SS_WEAK_DPI_RUS.txt", "BL"),
    ("igareck/vpn-configs-for-russia", "Vless-Reality-White-Lists-Rus-Mobile.txt", "WL"),
    ("igareck/vpn-configs-for-russia", "WHITE-CIDR-RU-checked.txt", "WL"),
    ("igareck/vpn-configs-for-russia", "WHITE-SNI-RU-all.txt", "WL"),
    ("igareck/vpn-configs-for-russia", "WHITE-CIDR-RU-all.txt", "WL"),
    # белые списки
    ("zieng2/wl", "vless_universal.txt", "WL"),
    ("zieng2/wl", "vless_lite.txt", "WL"),
    ("whoahaow/rjsxrd", "githubmirror/bypass/bypass-all.txt", "WL"),
    ("FLAT447/v2ray-lists", "WHITE_FULL.txt", "WL"),
    ("FLAT447/v2ray-lists", "BLACK_FULL.txt", "BL"),
    ("flaafix/AetrisVPN-white-list-lite", "AetrisVPN.txt", "WL"),
    ("flaafix/AetrisVPN", "AetrisVPN.txt", "MIX"),
    ("flaafix/AetrisVPN-black-list", "configs.txt", "BL"),
    ("wlunlocker/vpn-configs", "whitelist_all.txt", "WL"),
    ("wlunlocker/vpn-configs", "blacklist_all.txt", "BL"),
    ("Subzio/subzio", "WHITE_LIST_PROXY_COLLECTION.txt", "MIX"),
    ("solovyov-jenya2004/all_subs", "final_sorted", "MIX"),
    ("pie-with-jam/PulseProxy", "githubmirror/30.txt", "WL"),
    ("DarkRoyalty/shnajder-vpn-configs", "githubmirror/26.txt", "WL"),
    ("VOID-Anonymity/V.O.I.D-VPN_Bypass", "url_work.txt", "WL"),
    ("vladvarp/Prometheus", "WhiteList/vless.txt", "WL"),
    ("gooseteam-hackers/GooseVPN", "configs/balanced.txt", "WL"),
    ("gooseteam-hackers/GooseVPN", "configs/plus.txt", "WL"),
    ("Diversan313/apex-parser", "subs/main/alive_bs.txt", "WL"),
    ("Diversan313/apex-parser", "subs/main/alive_bl.txt", "BL"),
    ("RKPchannel/RKP_bypass_configs", "whitelist.txt", "WL"),
    ("RKPchannel/RKP_bypass_configs", "blacklist.txt", "BL"),
    ("terik21/HiddifySubs-VlessKeys", "WhiteKeys", "WL"),
    ("terik21/HiddifySubs-VlessKeys", "WhiteKeys2", "WL"),
    ("terik21/HiddifySubs-VlessKeys", "main", "BL"),
    ("terik21/HiddifySubs-VlessKeys", "SS", "BL"),
    ("terik21/HiddifySubs-VlessKeys", "Trojan", "BL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyakbeta6.txt", "WL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyakbeta6BL.txt", "BL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyakbeta7.txt", "BL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyakbeta8.txt", "BL"),
    ("Maskkost93/kizyak-vpn-4.0", "kizyaktestru.txt", "BL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni/vless.txt", "WL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni/trojan.txt", "WL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni/hysteria2.txt", "WL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni/hy2.txt", "WL"),
    ("kort0881/vpn-vless-configs-russia", "data/githubmirror/ru-sni-local/vless.txt", "WL"),
    ("kort0881/vpn-checker-backend", "checked/RU_Best/ru_white_all_WHITE.txt", "MIX"),
    ("kort0881/vpn-checker-backend", "checked/RU_Best/ru_white_all_BLACK.txt", "BL"),
    # смешанные / общие подборки с проверкой
    ("aviamastersgh/vpn-free-russia", "ru_configs.txt", "BL"),
    ("aviamastersgh/vpn-free-russia", "verified_configs.txt", "BL"),
    ("histeenn/VLESS-PO-GRIBI", "deploy/sub.txt", "BL"),
    ("svinakraft-maker/FlareFeed", "public/podpiska.txt", "BL"),
    ("luxxuria/harvester", "speed_tested.txt", "BL"),
    ("luxxuria/harvester", "ping_tested.txt", "BL"),
    ("luxxuria/harvester", "non_ru.txt", "BL"),
    ("tiagorrg/vless-checker", "docs/keys.json", "BL"),
]

# Справочные данные: диапазоны IP и домены из белых списков мобильных операторов, база стран
WHITELIST_CIDR = [
    ("pie-with-jam/PulseProxy", "source/config/cidrwhitelist.txt"),
    ("whoahaow/rjsxrd", "source/config/cidrwhitelist.txt"),
]
WHITELIST_SNI = [
    ("whoahaow/rjsxrd", "source/config/whitelist-all.txt"),
    ("pie-with-jam/PulseProxy", "source/config/sni_domains.json"),
]
GEOIP_MMDB = [  # первая доступная
    ("P3TERX/GeoLite.mmdb@download", "GeoLite2-Country.mmdb"),
    ("gooseteam-hackers/GooseVPN", "configs/GeoLite2-Country.mmdb"),
]
