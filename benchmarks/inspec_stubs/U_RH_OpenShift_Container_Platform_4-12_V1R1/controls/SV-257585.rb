control 'SV-257585' do
  title 'Red Hat Enterprise Linux CoreOS (RHCOS) must use USBGuard for hosts that include a USB Controller.'
  desc 'USBGuard adds an extra layer of security to the overall OpenShift infrastructure. It provides an additional control mechanism to prevent potential security threats originating from USB devices. By monitoring and controlling USB access, USBGuard helps mitigate risks associated with unauthorized or malicious devices that may attempt to exploit vulnerabilities within the system.'
  desc 'check', %q(1. Determine if the host devices include a USB Controller by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; lspci' 2>/dev/null; done

If there is not a USB Controller, then this requirement is Not Applicable.

2. Verify the USBGuard service is installed by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; rpm -q usbguard' 2>/dev/null; done

If the output returns "package usbguard is not installed", this is a finding.

3. Verify that USBGuard is set up to log into the Linux audit log.

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep -r AuditBackend /etc/usbguard/usbguard-daemon.conf' 2>/dev/null; done

The output should return:
"AuditBackend=LinuxAudit". If it does not, this is a finding.

4. Verify the USBGuard has a policy configured with by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; usbguard list-rules' 2>/dev/null; done

If USBGuard is not found or the results do not match the organizationally defined rules, this is a finding.)
  desc 'fix', 'If there is not a USB Controller, this requirement is Not Applicable.

1. Install the service by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 80-usbguard-extensions-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
  extensions:
    - usbguard
" | oc apply -f -
done

2. Wait for the nodes to reboot.
Note: (>oc get mcp) None of the pools should say Updating=true when the update is done.

3. Enable the service by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 80-usbguard-service-enable-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    systemd:
      units:
      - name: usbguard.service
        enabled: true
" | oc apply -f -
done

4. Configure USBGuard to log to the audit log:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
   name: 80-usbguard-daemon-conf-$mcpool
   labels:
     machineconfiguration.openshift.io/role: $mcpool
spec:
   config:
     ignition:
       version: 3.1.0
     storage:
       files:
       - contents:
           source: data:,%23%0A%23%20Rule%20set%20file%20path.%0A%23%0A%23%20The%20USBGuard%20daemon%20will%20use%20this%20file%20to%20load%20the%20policy%0A%23%20rule%20set%20from%20it%20and%20to%20write%20new%20rules%20received%20via%20the%0A%23%20IPC%20interface.%0A%23%0A%23%20RuleFile%3D%2Fpath%2Fto%2Frules.conf%0A%23%0ARuleFile%3D%2Fetc%2Fusbguard%2Frules.conf%0A%0A%23%0A%23%20Rule%20set%20folder%20path.%0A%23%0A%23%20The%20USBGuard%20daemon%20will%20use%20this%20folder%20to%20load%20the%20policy%0A%23%20rule%20set%20from%20it%20and%20to%20write%20new%20rules%20received%20via%20the%0A%23%20IPC%20interface.%20Usually%2C%20we%20set%20the%20option%20to%0A%23%20%2Fetc%2Fusbguard%2Frules.d%2F.%20The%20USBGuard%20daemon%20is%20supposed%20to%0A%23%20behave%20like%20any%20other%20standard%20Linux%20daemon%20therefore%20it%0A%23%20loads%20rule%20files%20in%20alpha-numeric%20order.%20File%20names%20inside%0A%23%20RuleFolder%20directory%20should%20start%20with%20a%20two-digit%20number%0A%23%20prefix%20indicating%20the%20position%2C%20in%20which%20the%20rules%20are%0A%23%20scanned%20by%20the%20daemon.%0A%23%0A%23%20RuleFolder%3D%2Fpath%2Fto%2Frulesfolder%2F%0A%23%0ARuleFolder%3D%2Fetc%2Fusbguard%2Frules.d%2F%0A%0A%23%0A%23%20Implicit%20policy%20target.%0A%23%0A%23%20How%20to%20treat%20devices%20that%20don%27t%20match%20any%20rule%20in%20the%0A%23%20policy.%20One%20of%3A%0A%23%0A%23%20%2A%20allow%20%20-%20authorize%20the%20device%0A%23%20%2A%20block%20%20-%20block%20the%20device%0A%23%20%2A%20reject%20-%20remove%20the%20device%0A%23%0AImplicitPolicyTarget%3Dblock%0A%0A%23%0A%23%20Present%20device%20policy.%0A%23%0A%23%20How%20to%20treat%20devices%20that%20are%20already%20connected%20when%20the%0A%23%20daemon%20starts.%20One%20of%3A%0A%23%0A%23%20%2A%20allow%20%20%20%20%20%20%20%20-%20authorize%20every%20present%20device%0A%23%20%2A%20block%20%20%20%20%20%20%20%20-%20deauthorize%20every%20present%20device%0A%23%20%2A%20reject%20%20%20%20%20%20%20-%20remove%20every%20present%20device%0A%23%20%2A%20keep%20%20%20%20%20%20%20%20%20-%20just%20sync%20the%20internal%20state%20and%20leave%20it%0A%23%20%2A%20apply-policy%20-%20evaluate%20the%20ruleset%20for%20every%20present%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20device%0A%23%0APresentDevicePolicy%3Dapply-policy%0A%0A%23%0A%23%20Present%20controller%20policy.%0A%23%0A%23%20How%20to%20treat%20USB%20controllers%20that%20are%20already%20connected%0A%23%20when%20the%20daemon%20starts.%20One%20of%3A%0A%23%0A%23%20%2A%20allow%20%20%20%20%20%20%20%20-%20authorize%20every%20present%20device%0A%23%20%2A%20block%20%20%20%20%20%20%20%20-%20deauthorize%20every%20present%20device%0A%23%20%2A%20reject%20%20%20%20%20%20%20-%20remove%20every%20present%20device%0A%23%20%2A%20keep%20%20%20%20%20%20%20%20%20-%20just%20sync%20the%20internal%20state%20and%20leave%20it%0A%23%20%2A%20apply-policy%20-%20evaluate%20the%20ruleset%20for%20every%20present%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20device%0A%23%0APresentControllerPolicy%3Dkeep%0A%0A%23%0A%23%20Inserted%20device%20policy.%0A%23%0A%23%20How%20to%20treat%20USB%20devices%20that%20are%20already%20connected%0A%23%20%2Aafter%2A%20the%20daemon%20starts.%20One%20of%3A%0A%23%0A%23%20%2A%20block%20%20%20%20%20%20%20%20-%20deauthorize%20every%20present%20device%0A%23%20%2A%20reject%20%20%20%20%20%20%20-%20remove%20every%20present%20device%0A%23%20%2A%20apply-policy%20-%20evaluate%20the%20ruleset%20for%20every%20present%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20device%0A%23%0AInsertedDevicePolicy%3Dapply-policy%0A%0A%23%0A%23%20Control%20which%20devices%20are%20authorized%20by%20default.%0A%23%0A%23%20The%20USBGuard%20daemon%20modifies%20some%20the%20default%20authorization%20state%20attributes%0A%23%20of%20controller%20devices.%20This%20setting%2C%20enables%20you%20to%20define%20what%20value%20the%0A%23%20default%20authorization%20is%20set%20to.%0A%23%0A%23%20%2A%20keep%20%20%20%20%20%20%20%20%20-%20do%20not%20change%20the%20authorization%20state%0A%23%20%2A%20none%20%20%20%20%20%20%20%20%20-%20every%20new%20device%20starts%20out%20deauthorized%0A%23%20%2A%20all%20%20%20%20%20%20%20%20%20%20-%20every%20new%20device%20starts%20out%20authorized%0A%23%20%2A%20internal%20%20%20%20%20-%20internal%20devices%20start%20out%20authorized%2C%20external%20devices%20start%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20out%20deauthorized%20%28this%20requires%20the%20ACPI%20tables%20to%20properly%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20label%20internal%20devices%2C%20and%20kernel%20support%29%0A%23%0A%23AuthorizedDefault%3Dnone%0A%0A%23%0A%23%20Restore%20controller%20device%20state.%0A%23%0A%23%20The%20USBGuard%20daemon%20modifies%20some%20attributes%20of%20controller%0A%23%20devices%20like%20the%20default%20authorization%20state%20of%20new%20child%20device%0A%23%20instances.%20Using%20this%20setting%2C%20you%20can%20control%20whether%20the%0A%23%20daemon%20will%20try%20to%20restore%20the%20attribute%20values%20to%20the%20state%0A%23%20before%20modification%20on%20shutdown.%0A%23%0A%23%20SECURITY%20CONSIDERATIONS%3A%20If%20set%20to%20true%2C%20the%20USB%20authorization%0A%23%20policy%20could%20be%20bypassed%20by%20performing%20some%20sort%20of%20attack%20on%20the%0A%23%20daemon%20%28via%20a%20local%20exploit%20or%20via%20a%20USB%20device%29%20to%20make%20it%20shutdown%0A%23%20and%20restore%20to%20the%20operating-system%20default%20state%20%28known%20to%20be%20permissive%29.%0A%23%0ARestoreControllerDeviceState%3Dfalse%0A%0A%23%0A%23%20Device%20manager%20backend%0A%23%0A%23%20Which%20device%20manager%20backend%20implementation%20to%20use.%20One%20of%3A%0A%23%0A%23%20%2A%20uevent%20%20%20-%20Netlink%20based%20implementation%20which%20uses%20sysfs%20to%20scan%20for%20present%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20devices%20and%20an%20uevent%20netlink%20socket%20for%20receiving%20USB%20device%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20related%20events.%0A%23%20%2A%20umockdev%20-%20umockdev%20based%20device%20manager%20capable%20of%20simulating%20devices%20based%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20on%20umockdev-record%20files.%20Useful%20for%20testing.%0A%23%0ADeviceManagerBackend%3Duevent%0A%0A%23%21%21%21%20WARNING%3A%20It%27s%20good%20practice%20to%20set%20at%20least%20one%20of%20the%20%21%21%21%0A%23%21%21%21%20%20%20%20%20%20%20%20%20%20two%20options%20bellow.%20If%20none%20of%20them%20are%20set%2C%20%20%21%21%21%0A%23%21%21%21%20%20%20%20%20%20%20%20%20%20the%20daemon%20will%20accept%20IPC%20connections%20from%20%20%20%21%21%21%0A%23%21%21%21%20%20%20%20%20%20%20%20%20%20anyone%2C%20thus%20allowing%20anyone%20to%20modify%20the%20%20%20%20%21%21%21%0A%23%21%21%21%20%20%20%20%20%20%20%20%20%20rule%20set%20and%20%28de%29authorize%20USB%20devices.%20%20%20%20%20%20%20%21%21%21%0A%0A%23%0A%23%20Users%20allowed%20to%20use%20the%20IPC%20interface.%0A%23%0A%23%20A%20space%20delimited%20list%20of%20usernames%20that%20the%20daemon%20will%0A%23%20accept%20IPC%20connections%20from.%0A%23%0A%23%20IPCAllowedUsers%3Dusername1%20username2%20...%0A%23%0AIPCAllowedUsers%3Droot%0A%0A%23%0A%23%20Groups%20allowed%20to%20use%20the%20IPC%20interface.%0A%23%0A%23%20A%20space%20delimited%20list%20of%20groupnames%20that%20the%20daemon%20will%0A%23%20accept%20IPC%20connections%20from.%0A%23%0A%23%20IPCAllowedGroups%3Dgroupname1%20groupname2%20...%0A%23%0AIPCAllowedGroups%3Dwheel%0A%0A%23%0A%23%20IPC%20access%20control%20definition%20files%20path.%0A%23%0A%23%20The%20files%20at%20this%20location%20will%20be%20interpreted%20by%20the%20daemon%0A%23%20as%20access%20control%20definition%20files.%20The%20%28base%29name%20of%20a%20file%0A%23%20should%20be%20in%20the%20form%3A%0A%23%0A%23%20%20%20%5Buser%5D%5B%3A%3Cgroup%3E%5D%0A%23%0A%23%20and%20should%20contain%20lines%20in%20the%20form%3A%0A%23%0A%23%20%20%20%3Csection%3E%3D%5Bprivilege%5D%20...%0A%23%0A%23%20This%20way%20each%20file%20defines%20who%20is%20able%20to%20connect%20to%20the%20IPC%0A%23%20bus%20and%20what%20privileges%20he%20has.%0A%23%0AIPCAccessControlFiles%3D%2Fetc%2Fusbguard%2FIPCAccessControl.d%2F%0A%0A%23%0A%23%20Generate%20device%20specific%20rules%20including%20the%20%22via-port%22%0A%23%20attribute.%0A%23%0A%23%20This%20option%20modifies%20the%20behavior%20of%20the%20allowDevice%0A%23%20action.%20When%20instructed%20to%20generate%20a%20permanent%20rule%2C%0A%23%20the%20action%20can%20generate%20a%20port%20specific%20rule.%20Because%0A%23%20some%20systems%20have%20unstable%20port%20numbering%2C%20the%20generated%0A%23%20rule%20might%20not%20match%20the%20device%20after%20rebooting%20the%20system.%0A%23%0A%23%20If%20set%20to%20false%2C%20the%20generated%20rule%20will%20still%20contain%0A%23%20the%20%22parent-hash%22%20attribute%20which%20also%20defines%20an%20association%0A%23%20to%20the%20parent%20device.%20See%20usbguard-rules.conf%285%29%20for%20more%0A%23%20details.%0A%23%0ADeviceRulesWithPort%3Dfalse%0A%0A%23%0A%23%20USBGuard%20Audit%20events%20log%20backend%0A%23%0A%23%20One%20of%3A%0A%23%0A%23%20%2A%20FileAudit%20-%20Log%20audit%20events%20into%20a%20file%20specified%20by%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20AuditFilePath%20setting%20%28see%20below%29%0A%23%20%2A%20LinuxAudit%20-%20Log%20audit%20events%20using%20the%20Linux%20Audit%0A%23%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20subsystem%20%28using%20audit_log_user_message%29%0A%23%0AAuditBackend%3DLinuxAudit%0A%0A%23%0A%23%20USBGuard%20audit%20events%20log%20file%20path.%0A%23%0A%23AuditFilePath%3D%2Fvar%2Flog%2Fusbguard%2Fusbguard-audit.log%0A%0A%23%0A%23%20Hides%20personally%20identifiable%20information%20such%20as%20device%20serial%20numbers%20and%0A%23%20hashes%20of%20descriptors%20%28which%20include%20the%20serial%20number%29%20from%20audit%20entries.%0A%23%0A%23HidePII%3Dfalse
         mode: 0600
         path: /etc/usbguard/usbguard-daemon.conf
         overwrite: true 
" | oc apply -f - 
done 

5. Create a USBGuard policy:

Below is an example policy. Replace the string in files.contents.source.data with an organizationally approved policy:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
   name: 80-usbguard-rules-conf-$mcpool
   labels:
     machineconfiguration.openshift.io/role: $mcpool
spec:
   config:
     ignition:
       version: 3.1.0
     storage:
       files:
       - contents:
           source: data:,allow%20with-interface%20one-of%20%7B%2003%3A00%3A01%2003%3A01%3A01%20%7D%20if%20%21allowed-matches%28with-interface%20one-of%20%7B%2003%3A00%3A01%2003%3A01%3A01%20%7D%29
         mode: 0600
         path: /etc/usbguard/rules.conf
         overwrite: true 
" | oc apply -f - 
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61320r921696_chk'
  tag severity: 'medium'
  tag gid: 'V-257585'
  tag rid: 'SV-257585r921698_rule'
  tag stig_id: 'CNTR-OS-001030'
  tag gtitle: 'SRG-APP-000141-CTR-000315'
  tag fix_id: 'F-61244r921697_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
