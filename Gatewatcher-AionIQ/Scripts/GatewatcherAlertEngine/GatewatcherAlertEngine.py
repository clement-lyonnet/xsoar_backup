import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import json


def gatewatcherAlertEngine() -> CommandResults:

    incident = demisto.incident()
    d = json.loads(str(incident['CustomFields']['GatewatcherRawEvent']))

    if d['event']['module'] == "active_cti":

        ret_fields = {
            "dns.query": d['dns']['query'],
            "flow.bytes_toclient": d['flow']['bytes_toclient'],
            "flow.bytes_toserver": d['flow']['bytes_toserver'],
            "flow.pkts_toclient": d['flow']['pkts_toclient'],
            "flow.pkts_toserver": d['flow']['pkts_toserver'],
            "flow.start": d['flow']['start'],
            "sigflow.action": d['sigflow']['action'],
            "sigflow.category": d['sigflow']['category'],
            "sigflow.gid": d['sigflow']['gid'],
            "sigflow.metadata": d['sigflow']['metadata'],
            "sigflow.payload": d['sigflow']['payload'],
            "sigflow.payload_printable": d['sigflow']['payload_printable'],
            "sigflow.rev": d['sigflow']['rev'],
            "sigflow.signature": d['sigflow']['signature'],
            "sigflow.signature_id": d['sigflow']['signature_id'],
            "sigflow.stream": d['sigflow']['stream']
        }

    if d['event']['module'] == "malcore":

        ret_fields = {
            "malcore.analyzed_clean": d['malcore']['analyzed_clean'],
            "malcore.analyzed_error": d['malcore']['analyzed_error'],
            "malcore.analyzed_infected": d['malcore']['analyzed_infected'],
            "malcore.analyzed_other": d['malcore']['analyzed_other'],
            "malcore.analyzed_suspicious": d['malcore']['analyzed_suspicious'],
            "malcore.analyzers_up": d['malcore']['analyzers_up'],
            "malcore.code": d['malcore']['code'],
            "malcore.detail_scan_time": d['malcore']['detail_scan_time'],
            "malcore.detail_threat_found": d['malcore']['detail_threat_found'],
            "malcore.detail_wait_time": d['malcore']['detail_wait_time'],
            "malcore.engine_id": d['malcore']['engine_id'],
            "malcore.engines_last_update_date": d['malcore']['engines_last_update_date'],
            "malcore.file_type": d['malcore']['file_type'],
            "malcore.file_type_description": d['malcore']['file_type_description'],
            "malcore.magic_details": d['malcore']['magic_details'],
            "malcore.processing_time": d['malcore']['processing_time'],
            "malcore.reporting_token": d['malcore']['reporting_token'],
            "malcore.state": d['malcore']['state'],
            "malcore.total_found": d['malcore']['total_found']
        }

    if d['event']['module'] == "malcore_retroanalyzer":

        ret_fields = {
            "malcore_retroanalyzer.analyzed_clean": d['malcore_retroanalyzer']['analyzed_clean'],
            "malcore_retroanalyzer.analyzed_error": d['malcore_retroanalyzer']['analyzed_error'],
            "malcore_retroanalyzer.analyzed_infected": d['malcore_retroanalyzer']['analyzed_infected'],
            "malcore_retroanalyzer.analyzed_other": d['malcore_retroanalyzer']['analyzed_other'],
            "malcore_retroanalyzer.analyzed_suspicious": d['malcore_retroanalyzer']['analyzed_suspicious'],
            "malcore_retroanalyzer.analyzers_up": d['malcore_retroanalyzer']['analyzers_up'],
            "malcore_retroanalyzer.code": d['malcore_retroanalyzer']['code'],
            "malcore_retroanalyzer.detail_scan_time": d['malcore_retroanalyzer']['detail_scan_time'],
            "malcore_retroanalyzer.detail_threat_found": d['malcore_retroanalyzer']['detail_threat_found'],
            "malcore_retroanalyzer.detail_wait_time": d['malcore_retroanalyzer']['detail_wait_time'],
            "malcore_retroanalyzer.engine_id": d['malcore_retroanalyzer']['engine_id'],
            "malcore_retroanalyzer.engines_last_update_date": d['malcore_retroanalyzer']['engines_last_update_date'],
            "malcore_retroanalyzer.file_type": d['malcore_retroanalyzer']['file_type'],
            "malcore_retroanalyzer.file_type_description": d['malcore_retroanalyzer']['file_type_description'],
            "malcore_retroanalyzer.magic_details": d['malcore_retroanalyzer']['magic_details'],
            "malcore_retroanalyzer.processing_time": d['malcore_retroanalyzer']['processing_time'],
            "malcore_retroanalyzer.reporting_token": d['malcore_retroanalyzer']['reporting_token'],
            "malcore_retroanalyzer.state": d['malcore_retroanalyzer']['state'],
            "malcore_retroanalyzer.total_found": d['malcore_retroanalyzer']['total_found']
        }

    if d['event']['module'] == "shellcode_detect":

        ret_fields = {
            "shellcode.encodings": "",
            "shellcode.sub_type": ""
        }
        ret_fields['shellcode.encodings'] = d['shellcode']['encodings']
        ret_fields['shellcode.sub_type'] = d['shellcode']['sub_type']

    if d['event']['module'] == "malicious_powershell_detect":

        ret_fields = {
            "malicious_powershell.proba_obfuscated": "",
            "malicious_powershell.score": ""
        }
        ret_fields['malicious_powershell.proba_obfuscated'] = d['malicious_powershell']['proba_obfuscated']
        ret_fields['malicious_powershell.score'] = d['malicious_powershell']['score']

    if d['event']['module'] == "sigflow_alert":

        ret_fields = {
            "sigflow.action": d['sigflow']['action'],
            "sigflow.category": d['sigflow']['category'],
            "sigflow.gid": d['sigflow']['gid'],
            "sigflow.metadata": d['sigflow']['metadata'],
            "sigflow.payload": d['sigflow']['payload'],
            "sigflow.payload_printable": d['sigflow']['payload_printable'],
            "sigflow.rev": d['sigflow']['rev'],
            "sigflow.signature": d['sigflow']['signature'],
            "sigflow.signature_id": d['sigflow']['signature_id'],
            "sigflow.stream": d['sigflow']['stream']
        }

    if d['event']['module'] == "dga_detect":

        ret_fields = {
            "dga.dga_count": "",
            "dga.dga_ratio": "",
            "dga.malware_behavior_confidence": "",
            "dga.nx_domain_count": "",
            "dga.top_DGA": ""
        }
        ret_fields['dga.dga_count'] = d['dga']['dga_count']
        ret_fields['dga.dga_ratio'] = d['dga']['dga_ratio']
        ret_fields['dga.malware_behavior_confidence'] = d['dga']['malware_behavior_confidence']
        ret_fields['dga.nx_domain_count'] = d['dga']['nx_domain_count']
        ret_fields['dga.top_DGA'] = d['dga']['top_DGA']

    if d['event']['module'] == "ioc":

        ret_fields = {
            "ioc.campaigns": "",
            "ioc.case_id": "",
            "ioc.categories": "",
            "ioc.creation_date": "",
            "ioc.description": "",
            "ioc.external_links": "",
            "ioc.families": "",
            "ioc.kill_chain_phases": "",
            "ioc.meta_data": "",
            "ioc.package_date": "",
            "ioc.relations": "",
            "ioc.signature": "",
            "ioc.tags": "",
            "ioc.targeted_countries": "",
            "ioc.targeted_organizations": "",
            "ioc.targeted_platforms": "",
            "ioc.targeted_sectors": "",
            "ioc.threat_actor": "",
            "ioc.tlp": "",
            "ioc.ttp": "",
            "ioc.type": "",
            "ioc.updated_date": "",
            "ioc.usage_mode": "",
            "ioc.value": "",
            "ioc.vulnerabilities": ""
        }
        ret_fields['ioc.campaigns'] = d['ioc']['campaigns']
        ret_fields['ioc.case_id'] = d['ioc']['case_id']
        ret_fields['ioc.categories'] = d['ioc']['categories']
        ret_fields['ioc.creation_date'] = d['ioc']['creation_date']
        ret_fields['ioc.description'] = d['ioc']['description']
        ret_fields['ioc.external_links'] = d['ioc']['external_links']
        ret_fields['ioc.families'] = d['ioc']['families']
        ret_fields['ioc.kill_chain_phases'] = d['ioc']['kill_chain_phases']
        ret_fields['ioc.meta_data'] = d['ioc']['meta_data']
        ret_fields['ioc.package_date'] = d['ioc']['package_date']
        ret_fields['ioc.relations'] = d['ioc']['relations']
        ret_fields['ioc.signature'] = d['ioc']['signature']
        ret_fields['ioc.tags'] = d['ioc']['tags']
        ret_fields['ioc.targeted_countries'] = d['ioc']['targeted_countries']
        ret_fields['ioc.targeted_organizations'] = d['ioc']['targeted_organizations']
        ret_fields['ioc.targeted_platforms'] = d['ioc']['targeted_platforms']
        ret_fields['ioc.targeted_sectors'] = d['ioc']['targeted_sectors']
        ret_fields['ioc.threat_actor'] = d['ioc']['threat_actor']
        ret_fields['ioc.tlp'] = d['ioc']['tlp']
        ret_fields['ioc.ttp'] = d['ioc']['ttp']
        ret_fields['ioc.type'] = d['ioc']['type']
        ret_fields['ioc.updated_date'] = d['ioc']['updated_date']
        ret_fields['ioc.usage_mode'] = d['ioc']['usage_mode']
        ret_fields['ioc.value'] = d['ioc']['value']
        ret_fields['ioc.vulnerabilities'] = d['ioc']['vulnerabilities']

    if d['event']['module'] == "ransomware_detect":

        ret_fields = {
            "ransomware.alert_threshold": "",
            "ransomware.malicious_behavior_confidence": "",
            "ransomware.session_score": ""
        }
        ret_fields['ransomware.alert_threshold'] = d['ransomware']['alert_threshold']
        ret_fields['ransomware.malicious_behavior_confidence'] = d['ransomware']['malicious_behavior_confidence']
        ret_fields['ransomware.session_score'] = d['ransomware']['session_score']

    if d['event']['module'] == "beacon_detect":

        ret_fields = {
            "beacon.active": "",
            "beacon.hostname_resolution": "",
            "beacon.id": "",
            "beacon.mean_time_interval": "",
            "beacon.possible_cnc": "",
            "beacon.session_count": "",
            "beacon.type": ""
        }
        ret_fields['beacon.active'] = d['beacon']['active']
        ret_fields['beacon.hostname_resolution'] = d['beacon']['hostname_resolution']
        ret_fields['beacon.id'] = d['beacon']['id']
        ret_fields['beacon.mean_time_interval'] = d['beacon']['mean_time_interval']
        ret_fields['beacon.possible_cnc'] = d['beacon']['possible_cnc']
        ret_fields['beacon.session_count'] = d['beacon']['session_count']
        ret_fields['beacon.type'] = d['beacon']['type']

    if d['event']['module'] == "retrohunt":

        ret_fields = {
            "ioc.campaigns": "",
            "ioc.case_id": "",
            "ioc.categories": "",
            "ioc.creation_date": "",
            "ioc.description": "",
            "ioc.external_links": "",
            "ioc.families": "",
            "ioc.kill_chain_phases": "",
            "ioc.meta_data": "",
            "ioc.package_date": "",
            "ioc.relations": "",
            "ioc.signature": "",
            "ioc.tags": "",
            "ioc.targeted_countries": "",
            "ioc.targeted_organizations": "",
            "ioc.targeted_platforms": "",
            "ioc.targeted_sectors": "",
            "ioc.threat_actor": "",
            "ioc.tlp": "",
            "ioc.ttp": "",
            "ioc.type": "",
            "ioc.updated_date": "",
            "ioc.usage_mode": "",
            "ioc.value": "",
            "ioc.vulnerabilities": "",
            "matched_event.content": "",
            "matched_event.id": ""
        }
        ret_fields['ioc.campaigns'] = d['ioc']['campaigns']
        ret_fields['ioc.case_id'] = d['ioc']['case_id']
        ret_fields['ioc.categories'] = d['ioc']['categories']
        ret_fields['ioc.creation_date'] = d['ioc']['creation_date']
        ret_fields['ioc.description'] = d['ioc']['description']
        ret_fields['ioc.external_links'] = d['ioc']['external_links']
        ret_fields['ioc.families'] = d['ioc']['families']
        ret_fields['ioc.kill_chain_phases'] = d['ioc']['kill_chain_phases']
        ret_fields['ioc.meta_data'] = d['ioc']['meta_data']
        ret_fields['ioc.package_date'] = d['ioc']['package_date']
        ret_fields['ioc.relations'] = d['ioc']['relations']
        ret_fields['ioc.signature'] = d['ioc']['signature']
        ret_fields['ioc.tags'] = d['ioc']['tags']
        ret_fields['ioc.targeted_countries'] = d['ioc']['targeted_countries']
        ret_fields['ioc.targeted_organizations'] = d['ioc']['targeted_organizations']
        ret_fields['ioc.targeted_platforms'] = d['ioc']['targeted_platforms']
        ret_fields['ioc.targeted_sectors'] = d['ioc']['targeted_sectors']
        ret_fields['ioc.threat_actor'] = d['ioc']['threat_actor']
        ret_fields['ioc.tlp'] = d['ioc']['tlp']
        ret_fields['ioc.ttp'] = d['ioc']['ttp']
        ret_fields['ioc.type'] = d['ioc']['type']
        ret_fields['ioc.updated_date'] = d['ioc']['updated_date']
        ret_fields['ioc.usage_mode'] = d['ioc']['usage_mode']
        ret_fields['ioc.value'] = d['ioc']['value']
        ret_fields['ioc.vulnerabilities'] = d['ioc']['vulnerabilities']
        ret_fields['matched_event.content'] = d['matched_event']['content']
        ret_fields['matched_event.id'] = d['matched_event']['id']

    return CommandResults(raw_response=ret_fields)


def main():
    try:
        return_results(gatewatcherAlertEngine())

    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute Gate. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
