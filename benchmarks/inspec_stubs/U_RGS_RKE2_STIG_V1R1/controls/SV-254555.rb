control 'SV-254555' do
  title 'Rancher RKE2 components must be configured in accordance with the security configuration settings based on DoD security configuration or implementation guidance, including SRGs, STIGs, NSA configuration guides, CTOs, and DTMs.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to modify an existing account. Auditing of account creation is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail documents the creation of application user accounts and, as required, notifies administrators and/or application when accounts are created. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

Within Rancher RKE2, audit data can be generated from any of the deployed container platform components. This audit data is important when there are issues, such as security incidents, that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to know where within the container platform the event occurred.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to offload those access control functions and focus on core application features and functionality.

'
  desc 'check', %q(Audit logging and policies:

1. On all hosts running RKE2 Server, run the command: 
kubectl get po -n kube-system -l component=kube-apiserver -o=jsonpath="{.items[*].spec.containers[*].command}"  

If --audit-policy-file is not set, this is a finding.      
If --audit-log-mode is not set or = "blocking-strict", this is a finding.                                                                                                                                                                                                                                                            

2. Ensure the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc./rancher/rke2/config.yaml, contains CIS profile setting. Run the following command:
cat /etc./rancher/rke2/config.yaml 

If a value for profile is not found, this is a finding. (Example: "profile: cis-1.6" )                                                                                                                                                                                                                                                                                                          

3. Check the contents of the audit-policy file.                                                                                                                                                                                                                                                                                                                                               
By default RKE2 expects the audit-policy file to be located at /etc./rancher/rke2/audit-policy.yaml; however, this location can be overridden in the /etc./rancher/rke2/config.yaml file with argument 'kube-apiserver-arg: "audit-policy-file=/etc./rancher/rke2/audit-policy.yaml"'.                                                                    

If the audit policy file does not exist or does not look like the following, this is a finding.                                                                                                                                                                                                                                                            

# Log all requests at the RequestResponse level.                                                                                                                                                                                                                                                                                                       
apiVersion: audit.k8s.io/vX (Where X is the latest apiVersion)                                                                                                                                                                                                                                                                                  
kind: Policy                                                                                                                                                                                                                                                                                                                                           
rules:                                                                                                                                                                                                                                                                                                                                                 
- level: RequestResponse)
  desc 'fix', "Audit logging and policies:

Edit the /etc./rancher/rke2/config.yaml file, and enable the audit policy:
audit-policy-file: /etc./rancher/rke2/audit-policy.yaml

1. Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc./rancher/rke2/config.yaml, so that it contains required configuration. 

--audit-policy-file= Path to the file that defines the audit policy configuration. (Example: /etc./rancher/rke2/audit-policy.yaml)
--audit-log-mode=blocking-strict

If configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server

2. Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc./rancher/rke2/config.yaml, so that it contains required configuration. For example:

profile: cis-1.6

If configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server

3. Edit the audit policy file, by default located at /etc./rancher/rke2/audit-policy.yaml to look like below:

# Log all requests at the RequestResponse level.
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: RequestResponse

If configuration files are updated on a host, restart the RKE2 Service. Run the command:
'systemctl restart rke2-server' for server hosts and
'systemctl restart rke2-agent' for agent hosts."
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58039r870264_chk'
  tag severity: 'medium'
  tag gid: 'V-254555'
  tag rid: 'SV-254555r870265_rule'
  tag stig_id: 'CNTR-R2-000060'
  tag gtitle: 'SRG-APP-000026-CTR-000070'
  tag fix_id: 'F-57988r859234_fix'
  tag satisfies: ['SRG-APP-000026-CTR-000070', 'SRG-APP-000027-CTR-000075', 'SRG-APP-000028-CTR-000080', 'SRG-APP-000092-CTR-000165', 'SRG-APP-000095-CTR-000170', 'SRG-APP-000096-CTR-000175', 'SRG-APP-000097-CTR-000180', 'SRG-APP-000098-CTR-000185', 'SRG-APP-000099-CTR-000190', 'SRG-APP-000100-CTR-000195', 'SRG-APP-000101-CTR-000205', 'SRG-APP-000319-CTR-000745', 'SRG-APP-000320-CTR-000750', 'SRG-APP-000343-CTR-000780', 'SRG-APP-000358-CTR-000805', 'SRG-APP-000374-CTR-000865', 'SRG-APP-000375-CTR-000870', 'SRG-APP-000381-CTR-000905', 'SRG-APP-000409-CTR-000990', 'SRG-APP-000492-CTR-001220', 'SRG-APP-000493-CTR-001225', 'SRG-APP-000494-CTR-001230', 'SRG-APP-000495-CTR-001235', 'SRG-APP-000496-CTR-001240', 'SRG-APP-000497-CTR-001245', 'SRG-APP-000498-CTR-001250', 'SRG-APP-000499-CTR-001255', 'SRG-APP-000500-CTR-001260', 'SRG-APP-000501-CTR-001265', 'SRG-APP-000502-CTR-001270', 'SRG-APP-000503-CTR-001275', 'SRG-APP-000504-CTR-001280', 'SRG-APP-000505-CTR-001285', 'SRG-APP-000506-CTR-001290', 'SRG-APP-000507-CTR-001295', 'SRG-APP-000508-CTR-001300', 'SRG-APP-000509-CTR-001305', 'SRG-APP-000510-CTR-001310', 'SRG-APP-000516-CTR-000790', 'SRG-APP-00516-CTR-001325']
  tag 'documentable'
  tag cci: ['CCI-000018', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000172', 'CCI-000366', 'CCI-001403', 'CCI-001404', 'CCI-001464', 'CCI-001487', 'CCI-001814', 'CCI-001851', 'CCI-001889', 'CCI-001890', 'CCI-002130', 'CCI-002234', 'CCI-002884']
  tag nist: ['AC-2 (4)', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-12 c', 'CM-6 b', 'AC-2 (4)', 'AC-2 (4)', 'AU-14 (1)', 'AU-3 f', 'CM-5 (1)', 'AU-4 (1)', 'AU-8 b', 'AU-8 b', 'AC-2 (4)', 'AC-6 (9)', 'MA-4 (1) (a)']
end
