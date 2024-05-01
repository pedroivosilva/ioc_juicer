from misp_handler import LatimerMISP2FGT
from keys import misp_url, misp_key, misp_verifycert, misp_fgt_tag, fgt_url, fgt_key
import json

if __name__ == '__main__':
    conn = LatimerMISP2FGT(misp_url=misp_url,
                           misp_key=misp_key,
                           misp_verifycert=misp_verifycert,
                           misp_fgt_tag=misp_fgt_tag,
                           fgt_url=fgt_url,
                           fgt_key=fgt_key)

    print(conn.get_misp_fw_tag_index())
