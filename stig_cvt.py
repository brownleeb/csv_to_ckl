#!/usr/bin/python3
import sys,csv

poc='This Security Technical Implementation Guide is published as a tool to improve the security of Department of Defense (DoD) information systems. The requirements are derived from the National Institute of Standards and Technology (NIST) 800-53 and related documents. Comments or proposed revisions to this document should be sent via email to the following address: disa.stig_spt@mail.mil.'
t2='\n'+'\t'*2
t3='\n'+'\t'*3
t4='\n'+'\t'*4
t5='\n'+'\t'*5
def header(h,f):
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n<!--DISA STIG Viewer :: 2.16-->\n<CHECKLIST>\n\t<ASSET>'+t2+'<ROLE>None</ROLE>'+t2+'<ASSET_TYPE>Computing</ASSET_TYPE>'+t2+'<MARKING>CUI</MARKING>'+t2+'<HOST_NAME>'+h[1]+'</HOST_NAME>'+t2+'<HOST_IP>'+h[2]+'</HOST_IP>'+t2+'<HOST_MAC>'+h[3]+'</HOST_MAC>'+t2+'<HOST_FQDN>'+h[32]+'</HOST_FQDN>'+t2+'<TARGET_COMMENT></TARGET_COMMENT>'+t2+'<TECH_AREA>'+h[0]+'</TECH_AREA>'+t2+'<TARGET_KEY>5394</TARGET_KEY>'+t2+'<WEB_OR_DATABASE>false</WEB_OR_DATABASE>'+t2+'<WEB_DB_SITE></WEB_DB_SITE>'+t2+'<WEB_DB_INSTANCE></WEB_DB_INSTANCE>\n\t</ASSET>\n\t<STIGS>\n')

def new_stig(s,f):
    ver=s[25][s[25].find('Version')+8:s[25].find('Release')-2]
    rel=s[25][s[25].find('Release'):]
    title=s[25][:s[25].find('::')-1]
    f.write('\t\t<iSTIG>'+t3+'<STIG_INFO>'+t4+'<SI_DATA>'+t5+'<SID_NAME>version</SID_NAME>'+t5+'<SID_DATA>'+ver+'</SID_DATA>'+t4+'</SI_DATA>'+t4+'<SI_DATA>'+t5+'<SID_NAME>classification</SID_NAME>'+t5+'<SID_DATA>UNCLASSIFIED</SID_DATA>'+t4+'</SI_DATA>'+t4+'<SI_DATA>'+t5+'<SID_NAME>customname</SID_NAME>'+t4+'</SI_DATA>'+t4+'<SI_DATA>'+t5+'<SID_NAME>stigid</SID_NAME>'+t5+'<SID_DATA>Network_WLAN_Controller_Mgmt_STIG</SID_DATA>'+t4+'</SI_DATA>'+t4+'<SI_DATA>'+t5+'<SID_NAME>description</SID_NAME>'+t5+'<SID_DATA>'+poc+'</SID_DATA>'+t4+'</SI_DATA>'+t4+'<SI_DATA>'+t5+'<SID_NAME>filename</SID_NAME>'+t5+'<SID_DATA>U_Network_WLAN_Controller_Mgmt_V7R1_Manual_STIG-xccdf.xml</SID_DATA>'+t4+'</SI_DATA>'+t4+'<SI_DATA>'+t5+'<SID_NAME>releaseinfo</SID_NAME>'+t5+'<SID_DATA>'+rel+'</SID_DATA>'+t4+'</SI_DATA>'+t4+'<SI_DATA>'+t5+'<SID_NAME>title</SID_NAME>'+t5+'<SID_DATA>'+title+'</SID_DATA>'+t4+'</SI_DATA>'+t4+'<SI_DATA>'+t5+'<SID_NAME>uuid</SID_NAME>'+t5+'<SID_DATA>0b893b75-3e86-4936-bc8c-46c2cd62ae9a</SID_DATA>'+t4+'</SI_DATA>'+t4+'<SI_DATA>'+t5+'<SID_NAME>notice</SID_NAME>'+t5+'<SID_DATA>terms-of-use</SID_DATA>'+t4+'</SI_DATA>\n\t\t\t\t<SI_DATA>'+t5+'<SID_NAME>source</SID_NAME>'+t5+'<SID_DATA>STIG.DOD.MIL</SID_DATA>'+t4+'</SI_DATA>'+t3+'</STIG_INFO>\n')

def vuln(s,f):
    cols=[4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,'10.0',24,25,'5398','d29fcfa5-bac2-4411-b553-143e41dec2a9',s[34][:s[34].find(';')],s[34][s[34].find(';')+2:],s[31][:10]]
    hdr= ['Vuln_Num','Severity','Group_Title','Rule_ID','Rule_Ver','Rule_Title','Vuln_Discuss','IA_Controls','Check_Content','Fix_Text','False_Positives','False_Negatives','Documentable','Mitigations','Potential_Impact','Third_Party_Tools','Mitigation_Control','Responsibility','Security_Override_Guidance','Check_Content_Ref','Weight','Class','STIGRef','TargetKey','STIG_UUID','LEGACY_ID','LEGACY_ID','CCI_REF']
    f.write('\t\t\t<VULN>\n')
    for c in range (0,28):
        if type(cols[c])==str:
            v=cols[c]
        else:
            v=s[cols[c]].replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
        f.write('\t\t\t\t<STIG_DATA>'+t5+'<VULN_ATTRIBUTE>'+hdr[c]+'</VULN_ATTRIBUTE>'+t5+'<ATTRIBUTE_DATA>'+v+'</ATTRIBUTE_DATA>'+t4+'</STIG_DATA>\n')
    if s[26]=='Not A Finding': status='NotAFinding'
    elif s[26]=='Open':  status='Open'
    elif s[26]=='Not Reviewed':  status='Not_Reviewed'
    else: status='Not_Applicable'
    f.write('\t\t\t\t<STATUS>'+status+'</STATUS>'+t4+'<FINDING_DETAILS>'+s[28]+'</FINDING_DETAILS>'+t4+'<COMMENTS>'+s[27]+'</COMMENTS>'+t4+'<SEVERITY_OVERRIDE>'+s[29]+'</SEVERITY_OVERRIDE>'+t4+'<SEVERITY_JUSTIFICATION>'+s[30]+'</SEVERITY_JUSTIFICATION>'+t3+'</VULN>\n')

in_csv=sys.argv[1]

#with open (in_csv,encoding='windows-1252') as f:
rows=[]
try:
    with open (in_csv) as f:
        reader=csv.reader(f)
        for row in reader:
            if ''.join(row).find('~~~~~   CUI   ~~~~~') == -1:
                rows.append(row)
#        lines=f.read().replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').splitlines()
except:
    print (rows[-5:])
stig=''
host=rows[1][1]
outfile=open(host+'.ckl','w')
header(rows[1],outfile)
first=True
for r in range(1,len(rows)):
    if rows[r][1]!=host:
        outfile.write('\t\t</iSTIG>\n\t</STIGS>\n</CHECKLIST>\n')
        outfile.close()
        print('closing '+host+'.ckl')
        outfile=open(rows[r][1]+'.ckl','w')
        header(rows[1],outfile)
        host=rows[r][1]
        new_stig(rows[r],outfile)
        stig=rows[r][25]
        first=False
    if rows[r][25]!=stig:
        if not first:
            outfile.write('\t\t</iSTIG>\n')
        new_stig(rows[r],outfile)
        stig=rows[r][25]
        first=False
    vuln(rows[r],outfile)
outfile.write('\t\t</iSTIG>\n\t</STIGS>\n</CHECKLIST>\n')
outfile.close()
print ('closed '+host+'.ckl')
