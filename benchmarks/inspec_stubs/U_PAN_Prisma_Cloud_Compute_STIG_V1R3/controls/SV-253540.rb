control 'SV-253540' do
  title 'Prisma Cloud Compute must prevent unauthorized and unintended information transfer.'
  desc 'Prisma Cloud Compute Compliance policies must be enabled to ensure running containers do not access privileged resources.

'
  desc 'check', %q(Navigate to Prisma Cloud Compute Console's Defend >> Compliance >> Containers and images tab >> Deployed tab. 

For each rule name, click the rule and confirm the following checks:
(Filter on ID)
ID = 54: Do not use privileged container
ID = 5525: Restrict container from acquiring additional privileges are not configured
ID = 59: Do not share the host's network namespace
ID = 515: Do not share the host's process namespace
ID = 516: Do not share the host's IPC namespace
ID = 517: Do not directly expose host devices to containers
ID = 520: Do not share the host's UTS namespace
ID = 530: Do not share the host's user namespaces
ID = 55: Do not mount sensitive host system directories on containers
ID = 57: Do not map privileged ports within containers
ID = 5510: Limit memory usage for container
ID = 5511: Set container CPU priority appropriately
ID = 599: Container is running as root
ID = 41 Image should be created with a non-root user

If the action for each rule is set to "Ignore", this is a finding.)
  desc 'fix', %q(Navigate to Prisma Cloud Compute Console's Defend >> Compliance >> Containers and images tab >> Deployed tab. 

Change action:
(Click the rule name)
<Filter on Rule ID>

ID = 54 - Description (Do not use privileged container)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 5525 - Description (Restrict container from acquiring additional privileges are not configured)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 59 - Description (Do not share the host's network namespace)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 515 - Description (Do not share the host's process namespace)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 516 - Description (Do not share the host's IPC namespace)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 517 - Description (Do not directly expose host devices to containers)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 520 - Description (Do not share the host's UTS namespace)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 530 - Description (Do not share the host's user namespaces)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 55 - Description (Do not mount sensitive host system directories on containers)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 57 - Description (Do not map privileged ports within containers)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 5510 - Description (Limit memory usage for container)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 5511 - Description (Set container CPU priority appropriately)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 599 - Description (Container is running as root)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".

ID = 41 - Description (Image should be created with a non-root user)
Change Action to "Alert" or "Block" (based on organizational needs).
Click "Save".)
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-56992r840456_chk'
  tag severity: 'medium'
  tag gid: 'V-253540'
  tag rid: 'SV-253540r879649_rule'
  tag stig_id: 'CNTR-PC-000850'
  tag gtitle: 'SRG-APP-000243-CTR-000595'
  tag fix_id: 'F-56943r840457_fix'
  tag satisfies: ['SRG-APP-000243-CTR-000595', 'SRG-APP-000243-CTR-000600', 'SRG-APP-000246-CTR-000605', 'SRG-APP-000342-CTR-000775']
  tag 'documentable'
  tag cci: ['CCI-001090', 'CCI-001094', 'CCI-002233']
  tag nist: ['SC-4', 'SC-5 (1)', 'AC-6 (8)']
end
