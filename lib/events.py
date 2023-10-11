SECUTIRY = {
    1102: 'Audit log was cleared. This can relate to a potential attack',
    4616: 'System time was changed',
    4624: 'Successful account log on',
    4625: 'Failed account log on',
    4634: 'An account logged off',
    4648: 'A logon attempt was made with explicit credentials',
    4657: 'A registry value was changed',
    4663: 'Attempt made to access object',
    4670: 'Permissions on an object were changed',
    4672: 'Special privileges assigned to new logon',
    4688: 'A new process has been created',
    4697: 'An attempt was made to install a service',
    4698: 'A scheduled task was created',
    4699: 'A scheduled task was deleted',
    4700: 'A scheduled task was enabled',
    4701: 'A scheduled task was disabled',
    4702: 'A scheduled task was updated',
    4719: 'System audit policy was changed.',
    4720: 'A user account was created',
    4722: 'A user account was enabled',
    4723: 'An attempt was made to change the password of an account',
    4725: 'A user account was disabled',
    4728: 'A user was added to a privileged global group',
    4732: 'A user was added to a privileged local group',
    4735: 'A privileged local group was modified',
    4737: 'A privileged global group was modified',
    4738: 'A user account was changed',
    4740: 'A user account was locked out',
    4755: 'A privileged universal group was modified',
    4756: 'A user was added to a privileged universal group',
    4767: 'A user account was unlocked',
    4772: 'A Kerberos authentication ticket request failed',
    4777: 'The domain controller failed to validate the credentials of an account.',  # nopep8
    4782: 'Password hash an account was accessed',
    4946: 'A rule was added to the Windows Firewall exception list',
    4947: 'A rule was modified in the Windows Firewall exception list',
    4950: 'A setting was changed in Windows Firewall',
    4954: 'Group Policy settings for Windows Firewall has changed',
    4964: 'A special group has been assigned to a new log on',
    5025: 'The Windows Firewall service has been stopped',
    5031: 'Windows Firewall blocked an application from accepting incoming traffic',  # nopep8
    5152: 'A network packet was blocked by Windows Filtering Platform',
    5153: 'A network packet was blocked by Windows Filtering Platform',
    5155: 'Windows Filtering Platform blocked an application or service from listening on a port',  # nopep8
    5157: 'Windows Filtering Platform blocked a connection',
    5447: 'A Windows Filtering Platform filter was changed',
    36871: 'A fatal error occurred while creating a TLS client or server credential'  # nopep8
}

WINDOWS = {
    1100: 'The event logging service has shut down',
    1101: 'Audit events have been dropped by the transport.',
    1102: 'The audit log was cleared',
    1104: 'The security Log is now full',
    1105: 'Event log automatic backup',
    1108: 'The event logging service encountered an error',
    4608: 'Windows is starting up',
    4609: 'Windows is shutting down',
    4610: 'An authentication package has been loaded by the Local Security Authority',  # nopep8
    4611: 'A trusted logon process has been registered with the Local Security Authority',  # nopep8
    4612: 'Internal resources allocated for the queuing of audit messages have been exhausted, leading to the loss of some audits.',  # nopep8
    4614: 'A notification package has been loaded by the Security Account Manager.',  # nopep8
    4615: 'Invalid use of LPC port',
    4616: 'The system time was changed.',
    4618: 'A monitored security event pattern has occurred',
    4621: 'Administrator recovered system from CrashOnAuditFail',
    4622: 'A security package has been loaded by the Local Security Authority.',  # nopep8
    4624: 'An account was successfully logged on',
    4625: 'An account failed to log on',
    4626: 'User/Device claims information',
    4627: 'Group membership information.',
    4634: 'An account was logged off',
    4646: 'IKE DoS-prevention mode started',
    4647: 'User initiated logoff',
    4648: 'A logon was attempted using explicit credentials',
    4649: 'A replay attack was detected',
    4650: 'An IPsec Main Mode security association was established',
    4651: 'An IPsec Main Mode security association was established',
    4652: 'An IPsec Main Mode negotiation failed',
    4653: 'An IPsec Main Mode negotiation failed',
    4654: 'An IPsec Quick Mode negotiation failed',
    4655: 'An IPsec Main Mode security association ended',
    4656: 'A handle to an object was requested',
    4657: 'A registry value was modified',
    4658: 'The handle to an object was closed',
    4659: 'A handle to an object was requested with intent to delete',
    4660: 'An object was deleted',
    4661: 'A handle to an object was requested',
    4662: 'An operation was performed on an object',
    4663: 'An attempt was made to access an object',
    4664: 'An attempt was made to create a hard link',
    4665: 'An attempt was made to create an application client context.',
    4666: 'An application attempted an operation',
    4667: 'An application client context was deleted',
    4668: 'An application was initialized',
    4670: 'Permissions on an object were changed',
    4671: 'An application attempted to access a blocked ordinal through the TBS',  # nopep8
    4672: 'Special privileges assigned to new logon',
    4673: 'A privileged service was called',
    4674: 'An operation was attempted on a privileged object',
    4675: 'SIDs were filtered',
    4688: 'A new process has been created',
    4689: 'A process has exited',
    4690: 'An attempt was made to duplicate a handle to an object',
    4691: 'Indirect access to an object was requested',
    4692: 'Backup of data protection master key was attempted',
    4693: 'Recovery of data protection master key was attempted',
    4694: 'Protection of auditable protected data was attempted',
    4695: 'Unprotection of auditable protected data was attempted',
    4696: 'A primary token was assigned to process',
    4697: 'A service was installed in the system',
    4698: 'A scheduled task was created',
    4699: 'A scheduled task was deleted',
    4700: 'A scheduled task was enabled',
    4701: 'A scheduled task was disabled',
    4702: 'A scheduled task was updated',
    4703: 'A token right was adjusted',
    4704: 'A user right was assigned',
    4705: 'A user right was removed',
    4706: 'A new trust was created to a domain',
    4707: 'A trust to a domain was removed',
    4709: 'IPsec Services was started',
    4710: 'IPsec Services was disabled',
    4711: 'PAStore Engine (1%)',
    4712: 'IPsec Services encountered a potentially serious failure',
    4713: 'Kerberos policy was changed',
    4714: 'Encrypted data recovery policy was changed',
    4715: 'The audit policy (SACL) on an object was changed',
    4716: 'Trusted domain information was modified',
    4717: 'System security access was granted to an account',
    4718: 'System security access was removed from an account',
    4719: 'System audit policy was changed',
    4720: 'A user account was created',
    4722: 'A user account was enabled',
    4723: 'An attempt was made to change an account\'s password',
    4724: 'An attempt was made to reset an accounts password',
    4725: 'A user account was disabled',
    4726: 'A user account was deleted',
    4727: 'A security-enabled global group was created',
    4728: 'A member was added to a security-enabled global group',
    4729: 'A member was removed from a security-enabled global group',
    4730: 'A security-enabled global group was deleted',
    4731: 'A security-enabled local group was created',
    4732: 'A member was added to a security-enabled local group',
    4733: 'A member was removed from a security-enabled local group',
    4734: 'A security-enabled local group was deleted',
    4735: 'A security-enabled local group was changed',
    4737: 'A security-enabled global group was changed',
    4738: 'A user account was changed',
    4739: 'Domain Policy was changed',
    4740: 'A user account was locked out',
    4741: 'A computer account was created',
    4742: 'A computer account was changed',
    4743: 'A computer account was deleted',
    4744: 'A security-disabled local group was created',
    4745: 'A security-disabled local group was changed',
    4746: 'A member was added to a security-disabled local group',
    4747: 'A member was removed from a security-disabled local group',
    4748: 'A security-disabled local group was deleted',
    4749: 'A security-disabled global group was created',
    4750: 'A security-disabled global group was changed',
    4751: 'A member was added to a security-disabled global group',
    4752: 'A member was removed from a security-disabled global group',
    4753: 'A security-disabled global group was deleted',
    4754: 'A security-enabled universal group was created',
    4755: 'A security-enabled universal group was changed',
    4756: 'A member was added to a security-enabled universal group',
    4757: 'A member was removed from a security-enabled universal group',
    4758: 'A security-enabled universal group was deleted',
    4759: 'A security-disabled universal group was created',
    4760: 'A security-disabled universal group was changed',
    4761: 'A member was added to a security-disabled universal group',
    4762: 'A member was removed from a security-disabled universal group',
    4763: 'A security-disabled universal group was deleted',
    4764: 'A groups type was changed',
    4765: 'SID History was added to an account',
    4766: 'An attempt to add SID History to an account failed',
    4767: 'A user account was unlocked',
    4768: 'A Kerberos authentication ticket (TGT) was requested',
    4769: 'A Kerberos service ticket was requested',
    4770: 'A Kerberos service ticket was renewed',
    4771: 'Kerberos pre-authentication failed',
    4772: 'A Kerberos authentication ticket request failed',
    4773: 'A Kerberos service ticket request failed',
    4774: 'An account was mapped for logon',
    4775: 'An account could not be mapped for logon',
    4776: 'The domain controller attempted to validate the credentials for an account',  # nopep8
    4777: 'The domain controller failed to validate the credentials for an account',  # nopep8
    4778: 'A session was reconnected to a Window Station',
    4779: 'A session was disconnected from a Window Station',
    4780: 'The ACL was set on accounts which are members of administrators groups',  # nopep8
    4781: 'The name of an account was changed',
    4782: 'The password hash an account was accessed',
    4783: 'A basic application group was created',
    4784: 'A basic application group was changed',
    4785: 'A member was added to a basic application group',
    4786: 'A member was removed from a basic application group',
    4787: 'A non-member was added to a basic application group',
    4788: 'A non-member was removed from a basic application group..',
    4789: 'A basic application group was deleted',
    4790: 'An LDAP query group was created',
    4791: 'A basic application group was changed',
    4792: 'An LDAP query group was deleted',
    4793: 'The Password Policy Checking API was called',
    4794: 'An attempt was made to set the Directory Services Restore Mode administrator password',  # nopep8
    4797: 'An attempt was made to query the existence of a blank password for an account',  # nopep8
    4798: 'A user\'s local group membership was enumerated.',
    4799: 'A security-enabled local group membership was enumerated',
    4800: 'The workstation was locked',
    4801: 'The workstation was unlocked',
    4802: 'The screen saver was invoked',
    4803: 'The screen saver was dismissed',
    4816: 'RPC detected an integrity violation while decrypting an incoming message',  # nopep8
    4817: 'Auditing settings on object were changed.',
    4818: 'Proposed Central Access Policy does not grant the same access permissions as the current Central Access Policy',  # nopep8
    4819: 'Central Access Policies on the machine have been changed',
    4820: 'A Kerberos Ticket-granting-ticket (TGT) was denied because the device does not meet the access control restrictions',  # nopep8
    4821: 'A Kerberos service ticket was denied because the user, device, or both does not meet the access control restrictions',  # nopep8
    4822: 'NTLM authentication failed because the account was a member of the Protected User group',  # nopep8
    4823: 'NTLM authentication failed because access control restrictions are required',  # nopep8
    4824: 'Kerberos preauthentication by using DES or RC4 failed because the account was a member of the Protected User group',  # nopep8
    4825: 'A user was denied the access to Remote Desktop. By default, users are allowed to connect only if they are members of the Remote Desktop Users group or Administrators group',  # nopep8
    4826: 'Boot Configuration Data loaded',
    4830: 'SID History was removed from an account',
    4864: 'A namespace collision was detected',
    4865: 'A trusted forest information entry was added',
    4866: 'A trusted forest information entry was removed',
    4867: 'A trusted forest information entry was modified',
    4868: 'The certificate manager denied a pending certificate request',
    4869: 'Certificate Services received a resubmitted certificate request',
    4870: 'Certificate Services revoked a certificate',
    4871: 'Certificate Services received a request to publish the certificate revocation list (CRL)',  # nopep8
    4872: 'Certificate Services published the certificate revocation list (CRL)',  # nopep8
    4873: 'A certificate request extension changed',
    4874: 'One or more certificate request attributes changed.',
    4875: 'Certificate Services received a request to shut down',
    4876: 'Certificate Services backup started',
    4877: 'Certificate Services backup completed',
    4878: 'Certificate Services restore started',
    4879: 'Certificate Services restore completed',
    4880: 'Certificate Services started',
    4881: 'Certificate Services stopped',
    4882: 'The security permissions for Certificate Services changed',
    4883: 'Certificate Services retrieved an archived key',
    4884: 'Certificate Services imported a certificate into its database',
    4885: 'The audit filter for Certificate Services changed',
    4886: 'Certificate Services received a certificate request',
    4887: 'Certificate Services approved a certificate request and issued a certificate',  # nopep8
    4888: 'Certificate Services denied a certificate request',
    4889: 'Certificate Services set the status of a certificate request to pending',  # nopep8
    4890: 'The certificate manager settings for Certificate Services changed.',
    4891: 'A configuration entry changed in Certificate Services',
    4892: 'A property of Certificate Services changed',
    4893: 'Certificate Services archived a key',
    4894: 'Certificate Services imported and archived a key',
    4895: 'Certificate Services published the CA certificate to Active Directory Domain Services',  # nopep8
    4896: 'One or more rows have been deleted from the certificate database',
    4897: 'Role separation enabled',
    4898: 'Certificate Services loaded a template',
    4899: 'A Certificate Services template was updated',
    4900: 'Certificate Services template security was updated',
    4902: 'The Per-user audit policy table was created',
    4904: 'An attempt was made to register a security event source',
    4905: 'An attempt was made to unregister a security event source',
    4906: 'The CrashOnAuditFail value has changed',
    4907: 'Auditing settings on object were changed',
    4908: 'Special Groups Logon table modified',
    4909: 'The local policy settings for the TBS were changed',
    4910: 'The group policy settings for the TBS were changed',
    4911: 'Resource attributes of the object were changed',
    4912: 'Per User Audit Policy was changed',
    4913: 'Central Access Policy on the object was changed',
    4928: 'An Active Directory replica source naming context was established',
    4929: 'An Active Directory replica source naming context was removed',
    4930: 'An Active Directory replica source naming context was modified',
    4931: 'An Active Directory replica destination naming context was modified',  # nopep8
    4932: 'Synchronization of a replica of an Active Directory naming context has begun',  # nopep8
    4933: 'Synchronization of a replica of an Active Directory naming context has ended',  # nopep8
    4934: 'Attributes of an Active Directory object were replicated',
    4935: 'Replication failure begins',
    4936: 'Replication failure ends',
    4937: 'A lingering object was removed from a replica',
    4944: 'The following policy was active when the Windows Firewall started',
    4945: 'A rule was listed when the Windows Firewall started',
    4946: 'A change has been made to Windows Firewall exception list. A rule was added',  # nopep8
    4947: 'A change has been made to Windows Firewall exception list. A rule was modified',  # nopep8
    4948: 'A change has been made to Windows Firewall exception list. A rule was deleted',  # nopep8
    4949: 'Windows Firewall settings were restored to the default values',
    4950: 'A Windows Firewall setting has changed',
    4951: 'A rule has been ignored because its major version number was not recognized by Windows Firewall',  # nopep8
    4952: 'Parts of a rule have been ignored because its minor version number was not recognized by Windows Firewall',  # nopep8
    4953: 'A rule has been ignored by Windows Firewall because it could not parse the rule',  # nopep8
    4954: 'Windows Firewall Group Policy settings has changed. The new settings have been applied',  # nopep8
    4956: 'Windows Firewall has changed the active profile',
    4957: 'Windows Firewall did not apply the following rule',
    4958: 'Windows Firewall did not apply the following rule because the rule referred to items not configured on this computer',  # nopep8
    4960: 'IPsec dropped an inbound packet that failed an integrity check',
    4961: 'IPsec dropped an inbound packet that failed a replay check',
    4962: 'IPsec dropped an inbound packet that failed a replay check',
    4963: 'IPsec dropped an inbound clear text packet that should have been secured',  # nopep8
    4964: 'Special groups have been assigned to a new logon',
    4965: 'IPsec received a packet from a remote computer with an incorrect Security Parameter Index (SPI).',  # nopep8
    4976: 'During Main Mode negotiation, IPsec received an invalid negotiation packet.',  # nopep8
    4977: 'During Quick Mode negotiation, IPsec received an invalid negotiation packet.',  # nopep8
    4978: 'During Extended Mode negotiation, IPsec received an invalid negotiation packet.',  # nopep8
    4979: 'IPsec Main Mode and Extended Mode security associations were established.',  # nopep8
    4980: 'IPsec Main Mode and Extended Mode security associations were established',  # nopep8
    4981: 'IPsec Main Mode and Extended Mode security associations were established',  # nopep8
    4982: 'IPsec Main Mode and Extended Mode security associations were established',  # nopep8
    4983: 'An IPsec Extended Mode negotiation failed',
    4984: 'An IPsec Extended Mode negotiation failed',
    4985: 'The state of a transaction has changed',
    5024: 'The Windows Firewall Service has started successfully',
    5025: 'The Windows Firewall Service has been stopped',
    5027: 'The Windows Firewall Service was unable to retrieve the security policy from the local storage',  # nopep8
    5028: 'The Windows Firewall Service was unable to parse the new security policy.',  # nopep8
    5029: 'The Windows Firewall Service failed to initialize the driver',
    5030: 'The Windows Firewall Service failed to start',
    5031: 'The Windows Firewall Service blocked an application from accepting incoming connections on the network.',  # nopep8
    5032: 'Windows Firewall was unable to notify the user that it blocked an application from accepting incoming connections on the network',  # nopep8
    5033: 'The Windows Firewall Driver has started successfully',
    5034: 'The Windows Firewall Driver has been stopped',
    5035: 'The Windows Firewall Driver failed to start',
    5037: 'The Windows Firewall Driver detected critical runtime error. Terminating',  # nopep8
    5038: 'Code integrity determined that the image hash of a file is not valid',  # nopep8
    5039: 'A registry key was virtualized.',
    5040: 'A change has been made to IPsec settings. An Authentication Set was added.',  # nopep8
    5041: 'A change has been made to IPsec settings. An Authentication Set was modified',  # nopep8
    5042: 'A change has been made to IPsec settings. An Authentication Set was deleted',  # nopep8
    5043: 'A change has been made to IPsec settings. A Connection Security Rule was added',  # nopep8
    5044: 'A change has been made to IPsec settings. A Connection Security Rule was modified',  # nopep8
    5045: 'A change has been made to IPsec settings. A Connection Security Rule was deleted',  # nopep8
    5046: 'A change has been made to IPsec settings. A Crypto Set was added',
    5047: 'A change has been made to IPsec settings. A Crypto Set was modified',  # nopep8
    5048: 'A change has been made to IPsec settings. A Crypto Set was deleted',
    5049: 'An IPsec Security Association was deleted',
    5050: 'An attempt to programmatically disable the Windows Firewall using a call to INetFwProfile.FirewallEnabled(FALSE',  # nopep8
    5051: 'A file was virtualized',
    5056: 'A cryptographic self test was performed',
    5057: 'A cryptographic primitive operation failed',
    5058: 'Key file operation',
    5059: 'Key migration operation',
    5060: 'Verification operation failed',
    5061: 'Cryptographic operation',
    5062: 'A kernel-mode cryptographic self test was performed',
    5063: 'A cryptographic provider operation was attempted',
    5064: 'A cryptographic context operation was attempted',
    5065: 'A cryptographic context modification was attempted',
    5066: 'A cryptographic function operation was attempted',
    5067: 'A cryptographic function modification was attempted',
    5068: 'A cryptographic function provider operation was attempted',
    5069: 'A cryptographic function property operation was attempted',
    5070: 'A cryptographic function property operation was attempted',
    5071: 'Key access denied by Microsoft key distribution service',
    5120: 'OCSP Responder Service Started',
    5121: 'OCSP Responder Service Stopped',
    5122: 'A Configuration entry changed in the OCSP Responder Service',
    5123: 'A configuration entry changed in the OCSP Responder Service',
    5124: 'A security setting was updated on OCSP Responder Service',
    5125: 'A request was submitted to OCSP Responder Service',
    5126: 'Signing Certificate was automatically updated by the OCSP Responder Service',  # nopep8
    5127: 'The OCSP Revocation Provider successfully updated the revocation information',  # nopep8
    5136: 'A directory service object was modified',
    5137: 'A directory service object was created',
    5138: 'A directory service object was undeleted',
    5139: 'A directory service object was moved',
    5140: 'A network share object was accessed',
    5141: 'A directory service object was deleted',
    5142: 'A network share object was added.',
    5143: 'A network share object was modified',
    5144: 'A network share object was deleted.',
    5145: 'A network share object was checked to see whether client can be granted desired access',  # nopep8
    5146: 'The Windows Filtering Platform has blocked a packet',
    5147: 'A more restrictive Windows Filtering Platform filter has blocked a packet',  # nopep8
    5148: 'The Windows Filtering Platform has detected a DoS attack and entered a defensive mode; packets associated with this attack will be discarded.',  # nopep8
    5149: 'The DoS attack has subsided and normal processing is being resumed.',  # nopep8
    5150: 'The Windows Filtering Platform has blocked a packet.',
    5151: 'A more restrictive Windows Filtering Platform filter has blocked a packet.',  # nopep8
    5152: 'The Windows Filtering Platform blocked a packet',
    5153: 'A more restrictive Windows Filtering Platform filter has blocked a packet',  # nopep8
    5154: 'The Windows Filtering Platform has permitted an application or service to listen on a port for incoming connections',  # nopep8
    5155: 'The Windows Filtering Platform has blocked an application or service from listening on a port for incoming connections',  # nopep8
    5156: 'The Windows Filtering Platform has allowed a connection',
    5157: 'The Windows Filtering Platform has blocked a connection',
    5158: 'The Windows Filtering Platform has permitted a bind to a local port',  # nopep8
    5159: 'The Windows Filtering Platform has blocked a bind to a local port',
    5168: 'Spn check for SMB/SMB2 fails.',
    5169: 'A directory service object was modified',
    5170: 'A directory service object was modified during a background cleanup task',  # nopep8
    5376: 'Credential Manager credentials were backed up',
    5377: 'Credential Manager credentials were restored from a backup',
    5378: 'The requested credentials delegation was disallowed by policy',
    5379: 'Credential Manager credentials were read',
    5380: 'Vault Find Credential',
    5381: 'Vault credentials were read',
    5382: 'Vault credentials were read',
    5440: 'The following callout was present when the Windows Filtering Platform Base Filtering Engine started',  # nopep8
    5441: 'The following filter was present when the Windows Filtering Platform Base Filtering Engine started',  # nopep8
    5442: 'The following provider was present when the Windows Filtering Platform Base Filtering Engine started',  # nopep8
    5443: 'The following provider context was present when the Windows Filtering Platform Base Filtering Engine started',  # nopep8
    5444: 'The following sub-layer was present when the Windows Filtering Platform Base Filtering Engine started',  # nopep8
    5446: 'A Windows Filtering Platform callout has been changed',
    5447: 'A Windows Filtering Platform filter has been changed',
    5448: 'A Windows Filtering Platform provider has been changed',
    5449: 'A Windows Filtering Platform provider context has been changed',
    5450: 'A Windows Filtering Platform sub-layer has been changed',
    5451: 'An IPsec Quick Mode security association was established',
    5452: 'An IPsec Quick Mode security association ended',
    5453: 'An IPsec negotiation with a remote computer failed because the IKE and AuthIP IPsec Keying Modules (IKEEXT) service is not started',  # nopep8
    5456: 'PAStore Engine applied Active Directory storage IPsec policy on the computer',  # nopep8
    5457: 'PAStore Engine failed to apply Active Directory storage IPsec policy on the computer',  # nopep8
    5458: 'PAStore Engine applied locally cached copy of Active Directory storage IPsec policy on the computer',  # nopep8
    5459: 'PAStore Engine failed to apply locally cached copy of Active Directory storage IPsec policy on the computer',  # nopep8
    5460: 'PAStore Engine applied local registry storage IPsec policy on the computer',  # nopep8
    5461: 'PAStore Engine failed to apply local registry storage IPsec policy on the computer',  # nopep8
    5462: 'PAStore Engine failed to apply some rules of the active IPsec policy on the computer',  # nopep8
    5463: 'PAStore Engine polled for changes to the active IPsec policy and detected no changes',  # nopep8
    5464: 'PAStore Engine polled for changes to the active IPsec policy, detected changes, and applied them to IPsec Services',  # nopep8
    5465: 'PAStore Engine received a control for forced reloading of IPsec policy and processed the control successfully',  # nopep8
    5466: 'PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory cannot be reached, and will use the cached copy of the Active Directory IPsec policy instead',   # nopep8
    5467: 'PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, and found no changes to the policy',  # nopep8
    5468: 'PAStore Engine polled for changes to the Active Directory IPsec policy, determined that Active Directory can be reached, found changes to the policy, and applied those changes',  # nopep8
    5471: 'PAStore Engine loaded local storage IPsec policy on the computer',
    5472: 'PAStore Engine failed to load local storage IPsec policy on the computer',  # nopep8
    5473: 'PAStore Engine loaded directory storage IPsec policy on the computer',  # nopep8
    5474: 'PAStore Engine failed to load directory storage IPsec policy on the computer',  # nopep8
    5477: 'PAStore Engine failed to add quick mode filter',
    5478: 'IPsec Services has started successfully',
    5479: 'IPsec Services has been shut down successfully',
    5480: 'IPsec Services failed to get the complete list of network interfaces on the computer',  # nopep8
    5483: 'IPsec Services failed to initialize RPC server. IPsec Services could not be started',  # nopep8
    5484: 'IPsec Services has experienced a critical failure and has been shut down',  # nopep8
    5485: 'IPsec Services failed to process some IPsec filters on a plug-and-play event for network interfaces',  # nopep8
    5632: 'A request was made to authenticate to a wireless network',
    5633: 'A request was made to authenticate to a wired network',
    5712: 'A Remote Procedure Call (RPC) was attempted',
    5888: 'An object in the COM+ Catalog was modified',
    5889: 'An object was deleted from the COM+ Catalog',
    5890: 'An object was added to the COM+ Catalog',
    6144: 'Security policy in the group policy objects has been applied successfully',  # nopep8
    6145: 'One or more errors occured while processing security policy in the group policy objects',  # nopep8
    6272: 'Network Policy Server granted access to a user',
    6273: 'Network Policy Server denied access to a user',
    6274: 'Network Policy Server discarded the request for a user',
    6275: 'Network Policy Server discarded the accounting request for a user',
    6276: 'Network Policy Server quarantined a user',
    6277: 'Network Policy Server granted access to a user but put it on probation because the host did not meet the defined health policy',  # nopep8
    6278: 'Network Policy Server granted full access to a user because the host met the defined health policy',  # nopep8
    6279: 'Network Policy Server locked the user account due to repeated failed authentication attempts',  # nopep8
    6280: 'Network Policy Server unlocked the user account',
    6281: 'Code Integrity determined that the page hashes of an image file are not valid...',  # nopep8
    6400: 'BranchCache: Received an incorrectly formatted response while discovering availability of content.',  # nopep8
    6401: 'BranchCache: Received invalid data from a peer. Data discarded.',
    6402: 'BranchCache: The message to the hosted cache offering it data is incorrectly formatted.',  # nopep8
    6403: 'BranchCache: The hosted cache sent an incorrectly formatted response to the client\'s message to offer it data.',  # nopep8
    6404: 'BranchCache: Hosted cache could not be authenticated using the provisioned SSL certificate.',  # nopep8
    6408: 'Registered product failed and Windows Firewall is now controlling the filtering for...',  # nopep8
    6409: 'BranchCache: A service connection point object could not be parsed',
    6410: 'Code integrity determined that a file does not meet the security requirements to load into a process. This could be due to the use of shared sections or other issues',  # nopep8
    6416: 'A new external device was recognized by the system.',
    6417: 'The FIPS mode crypto selftests succeeded',
    6418: 'The FIPS mode crypto selftests failed',
    6419: 'A request was made to disable a device',
    6420: 'A device was disabled',
    6421: 'A request was made to enable a device',
    6422: 'A device was enabled',
    6423: 'The installation of this device is forbidden by system policy',
    6424: 'The installation of this device was allowed, after having previously been forbidden by policy',  # nopep8
    8191: 'Highest System-Defined Audit Message Value',
}

SQL = {
    24000: 'SQL audit event',
    24001: 'Login succeeded (action_id LGIS)',
    24002: 'Logout succeeded (action_id LGO)',
    24003: 'Login failed (action_id LGIF)',
    24004: 'Change own password succeeded (action_id PWCS; class_type LX)',
    24005: 'Change own password failed (action_id PWCS; class_type LX)',
    24006: 'Change password succeeded (action_id PWC class_type LX)',
    24007: 'Change password failed (action_id PWC class_type LX)',
    24008: 'Reset own password succeeded (action_id PWRS; class_type LX)',
    24009: 'Reset own password failed (action_id PWRS; class_type LX)',
    24010: 'Reset password succeeded (action_id PWR; class_type LX)',
    24011: 'Reset password failed (action_id PWR; class_type LX)',
    24012: 'Must change password (action_id PWMC)',
    24013: 'Account unlocked (action_id PWU)',
    24014: 'Change application role password succeeded (action_id PWC; class_type AR)',  # nopep8
    24015: 'Change application role password failed (action_id PWC class_type AR)',  # nopep8
    24016: 'Add member to server role succeeded (action_id APRL class_type SG)',  # nopep8
    24017: 'Add member to server role failed (action_id APRL class_type SG)',
    24018: 'Remove member from server role succeeded (action_id DPRL class_type SG)',  # nopep8
    24019: 'Remove member from server role failed (action_id DPRL class_type SG)',  # nopep8
    24020: 'Add member to database role succeeded (action_id APRL class_type RL)',  # nopep8
    24021: 'Add member to database role failed (action_id APRL class_type RL)',
    24022: 'Remove member from database role succeeded (action_id DPRL class_type RL)',  # nopep8
    24023: 'Remove member from database role failed (action_id DPRL class_type RL)',  # nopep8
    24024: 'Issued database backup command (action_id BA class_type DB)',
    24025: 'Issued transaction log backup command (action_id BAL)',
    24026: 'Issued database restore command (action_id RS class_type DB)',
    24027: 'Issued transaction log restore command (action_id RS class_type DB)',  # nopep8
    24028: 'Issued database console command (action_id DBCC)',
    24029: 'Issued a bulk administration command (action_id ADBO)',
    24030: 'Issued an alter connection command (action_id ALCN)',
    24031: 'Issued an alter resources command (action_id ALRS)',
    24032: 'Issued an alter server state command (action_id ALSS)',
    24033: 'Issued an alter server settings command (action_id ALST)',
    24034: 'Issued a view server state command (action_id VSST)',
    24035: 'Issued an external access assembly command (action_id XA)',
    24036: 'Issued an unsafe assembly command (action_id XU)',
    24037: 'Issued an alter resource governor command (action_id ALRS class_type RG)',  # nopep8
    24038: 'Issued a database authenticate command (action_id AUTH)',
    24039: 'Issued a database checkpoint command (action_id CP)',
    24040: 'Issued a database show plan command (action_id SPLN)',
    24041: 'Issued a subscribe to query information command (action_id SUQN)',
    24042: 'Issued a view database state command (action_id VDST)',
    24043: 'Issued a change server audit command (action_id AL class_type A)',
    24044: 'Issued a change server audit specification command (action_id AL class_type SA)',  # nopep8
    24045: 'Issued a change database audit specification command (action_id AL class_type DA)',  # nopep8
    24046: 'Issued a create server audit command (action_id CR class_type A)',
    24047: 'Issued a create server audit specification command (action_id CR class_type SA)',  # nopep8
    24048: 'Issued a create database audit specification command (action_id CR class_type DA)',  # nopep8
    24049: 'Issued a delete server audit command (action_id DR class_type A)',
    24050: 'Issued a delete server audit specification command (action_id DR class_type SA)',  # nopep8
    24051: 'Issued a delete database audit specification command (action_id DR class_type DA)',  # nopep8
    24052: 'Audit failure (action_id AUSF)',
    24053: 'Audit session changed (action_id AUSC)',
    24054: 'Started SQL server (action_id SVSR)',
    24055: 'Paused SQL server (action_id SVPD)',
    24056: 'Resumed SQL server (action_id SVCN)',
    24057: 'Stopped SQL server (action_id SVSD)',
    24058: 'Issued a create server object command (action_id CR; class_type AG, EP, SD, SE, T)',  # nopep8
    24059: 'Issued a change server object command (action_id AL; class_type AG, EP, SD, SE, T)',  # nopep8
    24060: 'Issued a delete server object command (action_id DR; class_type AG, EP, SD, SE, T)',  # nopep8
    24061: 'Issued a create server setting command (action_id CR class_type SR)',  # nopep8
    24062: 'Issued a change server setting command (action_id AL class_type SR)',  # nopep8
    24063: 'Issued a delete server setting command (action_id DR class_type SR)',  # nopep8
    24064: 'Issued a create server cryptographic provider command (action_id CR class_type CP)',  # nopep8
    24065: 'Issued a delete server cryptographic provider command (action_id DR class_type CP)',  # nopep8
    24066: 'Issued a change server cryptographic provider command (action_id AL class_type CP)',  # nopep8
    24067: 'Issued a create server credential command (action_id CR class_type CD)',  # nopep8
    24068: 'Issued a delete server credential command (action_id DR class_type CD)',  # nopep8
    24069: 'Issued a change server credential command (action_id AL class_type CD)',  # nopep8
    24070: 'Issued a change server master key command (action_id AL class_type MK)',  # nopep8
    24071: 'Issued a back up server master key command (action_id BA class_type MK)',  # nopep8
    24072: 'Issued a restore server master key command (action_id RS class_type MK)',  # nopep8
    24073: 'Issued a map server credential to login command (action_id CMLG)',  # nopep8
    24074: 'Issued a remove map between server credential and login command (action_id NMLG)',  # nopep8
    24075: 'Issued a create server principal command (action_id CR class_type LX, SL)',  # nopep8
    24076: 'Issued a delete server principal command (action_id DR class_type LX, SL)',  # nopep8
    24077: 'Issued a change server principal credentials command (action_id CCLG)',  # nopep8
    24078: 'Issued a disable server principal command (action_id LGDA)',
    24079: 'Issued a change server principal default database command (action_id LGDB)',  # nopep8
    24080: 'Issued an enable server principal command (action_id LGEA)',
    24081: 'Issued a change server principal default language command (action_id LGLG)',  # nopep8
    24082: 'Issued a change server principal password expiration command (action_id PWEX)',  # nopep8
    24083: 'Issued a change server principal password policy command (action_id PWPL)',  # nopep8
    24084: 'Issued a change server principal name command (action_id LGNM)',
    24085: 'Issued a create database command (action_id CR class_type DB)',
    24086: 'Issued a change database command (action_id AL class_type DB)',
    24087: 'Issued a delete database command (action_id DR class_type DB)',
    24088: 'Issued a create certificate command (action_id CR class_type CR)',
    24089: 'Issued a change certificate command (action_id AL class_type CR)',
    24090: 'Issued a delete certificate command (action_id DR class_type CR)',
    24091: 'Issued a back up certificate command (action_id BA class_type CR)',
    24092: 'Issued an access certificate command (action_id AS class_type CR)',
    24093: 'Issued a create asymmetric key command (action_id CR class_type AK)',  # nopep8
    24094: 'Issued a change asymmetric key command (action_id AL class_type AK)',  # nopep8
    24095: 'Issued a delete asymmetric key command (action_id DR class_type AK)',  # nopep8
    24096: 'Issued an access asymmetric key command (action_id AS class_type AK)',  # nopep8
    24097: 'Issued a create database master key command (action_id CR class_type MK)',  # nopep8
    24098: 'Issued a change database master key command (action_id AL class_type MK)',  # nopep8
    24099: 'Issued a delete database master key command (action_id DR class_type MK)',  # nopep8
    24100: 'Issued a back up database master key command (action_id BA class_type MK)',  # nopep8
    24101: 'Issued a restore database master key command (action_id RS class_type MK)',  # nopep8
    24102: 'Issued an open database master key command (action_id OP class_type MK)',  # nopep8
    24103: 'Issued a create database symmetric key command (action_id CR class_type SK)',  # nopep8
    24104: 'Issued a change database symmetric key command (action_id AL class_type SK)',  # nopep8
    24105: 'Issued a delete database symmetric key command (action_id DR class_type SK)',  # nopep8
    24106: 'Issued a back up database symmetric key command (action_id BA class_type SK)',  # nopep8
    24107: 'Issued an open database symmetric key command (action_id OP class_type SK)',  # nopep8
    24108: 'Issued a create database object command (action_id CR)',
    24109: 'Issued a change database object command (action_id AL)',
    24110: 'Issued a delete database object command (action_id DR)',
    24111: 'Issued an access database object command (action_id AS)',
    24112: 'Issued a create assembly command (action_id CR class_type AS)',
    24113: 'Issued a change assembly command (action_id AL class_type AS)',
    24114: 'Issued a delete assembly command (action_id DR class_type AS)',
    24115: 'Issued a create schema command (action_id CR class_type SC)',
    24116: 'Issued a change schema command (action_id AL class_type SC)',
    24117: 'Issued a delete schema command (action_id DR class_type SC)',
    24118: 'Issued a create database encryption key command (action_id CR class_type DK)',  # nopep8
    24119: 'Issued a change database encryption key command (action_id AL class_type DK)',  # nopep8
    24120: 'Issued a delete database encryption key command (action_id DR class_type DK)',  # nopep8
    24121: 'Issued a create database user command (action_id CR; class_type US)',  # nopep8
    24122: 'Issued a change database user command (action_id AL; class_type US)',  # nopep8
    24123: 'Issued a delete database user command (action_id DR; class_type US)',  # nopep8
    24124: 'Issued a create database role command (action_id CR class_type RL)',  # nopep8
    24125: 'Issued a change database role command (action_id AL class_type RL)',  # nopep8
    24126: 'Issued a delete database role command (action_id DR class_type RL)',  # nopep8
    24127: 'Issued a create application role command (action_id CR class_type AR)',  # nopep8
    24128: 'Issued a change application role command (action_id AL class_type AR)',  # nopep8
    24129: 'Issued a delete application role command (action_id DR class_type AR)',  # nopep8
    24130: 'Issued a change database user login command (action_id USAF)',
    24131: 'Issued an auto-change database user login command (action_id USLG)',  # nopep8
    24132: 'Issued a create schema object command (action_id CR class_type D)',
    24133: 'Issued a change schema object command (action_id AL class_type D)',
    24134: 'Issued a delete schema object command (action_id DR class_type D)',
    24135: 'Issued a transfer schema object command (action_id TRO class_type D)',  # nopep8
    24136: 'Issued a create schema type command (action_id CR class_type TY)',
    24137: 'Issued a change schema type command (action_id AL class_type TY)',
    24138: 'Issued a delete schema type command (action_id DR class_type TY)',
    24139: 'Issued a transfer schema type command (action_id TRO class_type TY)',  # nopep8
    24140: 'Issued a create XML schema collection command (action_id CR class_type SX)',  # nopep8
    24141: 'Issued a change XML schema collection command (action_id AL class_type SX)',  # nopep8
    24142: 'Issued a delete XML schema collection command (action_id DR class_type SX)',  # nopep8
    24143: 'Issued a transfer XML schema collection command (action_id TRO class_type SX)',  # nopep8
    24144: 'Issued an impersonate within server scope command (action_id IMP; class_type LX)',  # nopep8
    24145: 'Issued an impersonate within database scope command (action_id IMP; class_type US)',  # nopep8
    24146: 'Issued a change server object owner command (action_id TO class_type SG)',  # nopep8
    24147: 'Issued a change database owner command (action_id TO class_type DB)',  # nopep8
    24148: 'Issued a change schema owner command (action_id TO class_type SC)',
    24150: 'Issued a change role owner command (action_id TO class_type RL)',
    24151: 'Issued a change database object owner command (action_id TO)',
    24152: 'Issued a change symmetric key owner command (action_id TO class_type SK)',  # nopep8
    24153: 'Issued a change certificate owner command (action_id TO class_type CR)',  # nopep8
    24154: 'Issued a change asymmetric key owner command (action_id TO class_type AK)',  # nopep8
    24155: 'Issued a change schema object owner command (action_id TO class_type OB)',  # nopep8
    24156: 'Issued a change schema type owner command (action_id TO class_type TY)',  # nopep8
    24157: 'Issued a change XML schema collection owner command (action_id TO class_type SX)',  # nopep8
    24158: 'Grant server permissions succeeded (action_id G class_type SR)',
    24159: 'Grant server permissions failed (action_id G class_type SR)',
    24160: 'Grant server permissions with grant succeeded (action_id GWG class_type SR)',  # nopep8
    24161: 'Grant server permissions with grant failed (action_id GWG class_type SR)',  # nopep8
    24162: 'Deny server permissions succeeded (action_id D class_type SR)',
    24163: 'Deny server permissions failed (action_id D class_type SR)',
    24164: 'Deny server permissions with cascade succeeded (action_id DWC class_type SR)',  # nopep8
    24165: 'Deny server permissions with cascade failed (action_id DWC class_type SR)',  # nopep8
    24166: 'Revoke server permissions succeeded (action_id R class_type SR)',
    24167: 'Revoke server permissions failed (action_id R class_type SR)',
    24168: 'Revoke server permissions with grant succeeded (action_id RWG class_type SR)',  # nopep8
    24169: 'Revoke server permissions with grant failed (action_id RWG class_type SR)',  # nopep8
    24170: 'Revoke server permissions with cascade succeeded (action_id RWC class_type SR)',  # nopep8
    24171: 'Revoke server permissions with cascade failed (action_id RWC class_type SR)',  # nopep8
    24172: 'Issued grant server object permissions command (action_id G; class_type LX)',  # nopep8
    24173: 'Issued grant server object permissions with grant command (action_id GWG; class_type LX)',  # nopep8
    24174: 'Issued deny server object permissions command (action_id D; class_type LX)',  # nopep8
    24175: 'Issued deny server object permissions with cascade command (action_id DWC; class_type LX)',  # nopep8
    24176: 'Issued revoke server object permissions command (action_id R; class_type LX)',  # nopep8
    24177: 'Issued revoke server object permissions with grant command (action_id; RWG class_type LX)',  # nopep8
    24178: 'Issued revoke server object permissions with cascade command (action_id RWC; class_type LX)',  # nopep8
    24179: 'Grant database permissions succeeded (action_id G class_type DB)',
    24180: 'Grant database permissions failed (action_id G class_type DB)',
    24181: 'Grant database permissions with grant succeeded (action_id GWG class_type DB)',  # nopep8
    24182: 'Grant database permissions with grant failed (action_id GWG class_type DB)',  # nopep8
    24183: 'Deny database permissions succeeded (action_id D class_type DB)',
    24184: 'Deny database permissions failed (action_id D class_type DB)',
    24185: 'Deny database permissions with cascade succeeded (action_id DWC class_type DB)',  # nopep8
    24186: 'Deny database permissions with cascade failed (action_id DWC class_type DB)',  # nopep8
    24187: 'Revoke database permissions succeeded (action_id R class_type DB)',
    24188: 'Revoke database permissions failed (action_id R class_type DB)',
    24189: 'Revoke database permissions with grant succeeded (action_id RWG class_type DB)',  # nopep8
    24190: 'Revoke database permissions with grant failed (action_id RWG class_type DB)',  # nopep8
    24191: 'Revoke database permissions with cascade succeeded (action_id RWC class_type DB)',  # nopep8
    24192: 'Revoke database permissions with cascade failed (action_id RWC class_type DB)',  # nopep8
    24193: 'Issued grant database object permissions command (action_id G class_type US)',  # nopep8
    24194: 'Issued grant database object permissions with grant command (action_id GWG; class_type US)',  # nopep8
    24195: 'Issued deny database object permissions command (action_id D; class_type US)',  # nopep8
    24196: 'Issued deny database object permissions with cascade command (action_id DWC; class_type US)',  # nopep8
    24197: 'Issued revoke database object permissions command (action_id R; class_type US)',  # nopep8
    24198: 'Issued revoke database object permissions with grant command (action_id RWG; class_type US)',  # nopep8
    24199: 'Issued revoke database object permissions with cascade command (action_id RWC; class_type US)',  # nopep8
    24200: 'Issued grant schema permissions command (action_id G class_type SC)',  # nopep8
    24201: 'Issued grant schema permissions with grant command (action_id GWG class_type SC)',  # nopep8
    24202: 'Issued deny schema permissions command (action_id D class_type SC)',  # nopep8
    24203: 'Issued deny schema permissions with cascade command (action_id DWC class_type SC)',  # nopep8
    24204: 'Issued revoke schema permissions command (action_id R class_type SC)',  # nopep8
    24205: 'Issued revoke schema permissions with grant command (action_id RWG class_type SC)',  # nopep8
    24206: 'Issued revoke schema permissions with cascade command (action_id RWC class_type SC)',  # nopep8
    24207: 'Issued grant assembly permissions command (action_id G class_type AS)',  # nopep8
    24208: 'Issued grant assembly permissions with grant command (action_id GWG class_type AS)',  # nopep8
    24209: 'Issued deny assembly permissions command (action_id D class_type AS)',  # nopep8
    24210: 'Issued deny assembly permissions with cascade command (action_id DWC class_type AS)',  # nopep8
    24211: 'Issued revoke assembly permissions command (action_id R class_type AS)',  # nopep8
    24212: 'Issued revoke assembly permissions with grant command (action_id RWG class_type AS)',  # nopep8
    24213: 'Issued revoke assembly permissions with cascade command (action_id RWC class_type AS)',  # nopep8
    24214: 'Issued grant database role permissions command (action_id G class_type RL)',  # nopep8
    24215: 'Issued grant database role permissions with grant command (action_id GWG class_type RL)',  # nopep8
    24216: 'Issued deny database role permissions command (action_id D class_type RL)',  # nopep8
    24217: 'Issued deny database role permissions with cascade command (action_id DWC class_type RL)',  # nopep8
    24218: 'Issued revoke database role permissions command (action_id R class_type RL)',  # nopep8
    24219: 'Issued revoke database role permissions with grant command (action_id RWG class_type RL)',  # nopep8
    24220: 'Issued revoke database role permissions with cascade command (action_id RWC class_type RL)',  # nopep8
    24221: 'Issued grant application role permissions command (action_id G class_type AR)',  # nopep8
    24222: 'Issued grant application role permissions with grant command (action_id GWG class_type AR)',  # nopep8
    24223: 'Issued deny application role permissions command (action_id D class_type AR)',  # nopep8
    24224: 'Issued deny application role permissions with cascade command (action_id DWC class_type AR)',  # nopep8
    24225: 'Issued revoke application role permissions command (action_id R class_type AR)',  # nopep8
    24226: 'Issued revoke application role permissions with grant command (action_id RWG class_type AR)',  # nopep8
    24227: 'Issued revoke application role permissions with cascade command (action_id RWC class_type AR)',  # nopep8
    24228: 'Issued grant symmetric key permissions command (action_id G class_type SK)',  # nopep8
    24229: 'Issued grant symmetric key permissions with grant command (action_id GWG class_type SK)',  # nopep8
    24230: 'Issued deny symmetric key permissions command (action_id D class_type SK)',  # nopep8
    24231: 'Issued deny symmetric key permissions with cascade command (action_id DWC class_type SK)',  # nopep8
    24232: 'Issued revoke symmetric key permissions command (action_id R class_type SK)',  # nopep8
    24233: 'Issued revoke symmetric key permissions with grant command (action_id RWG class_type SK)',  # nopep8
    24234: 'Issued revoke symmetric key permissions with cascade command (action_id RWC class_type SK)',  # nopep8
    24235: 'Issued grant certificate permissions command (action_id G class_type CR)',  # nopep8
    24236: 'Issued grant certificate permissions with grant command (action_id GWG class_type CR)',  # nopep8
    24237: 'Issued deny certificate permissions command (action_id D class_type CR)',  # nopep8
    24238: 'Issued deny certificate permissions with cascade command (action_id DWC class_type CR)',  # nopep8
    24239: 'Issued revoke certificate permissions command (action_id R class_type CR)',  # nopep8
    24240: 'Issued revoke certificate permissions with grant command (action_id RWG class_type CR)',  # nopep8
    24241: 'Issued revoke certificate permissions with cascade command (action_id RWC class_type CR)',  # nopep8
    24242: 'Issued grant asymmetric key permissions command (action_id G class_type AK)',  # nopep8
    24243: 'Issued grant asymmetric key permissions with grant command (action_id GWG class_type AK)',  # nopep8
    24244: 'Issued deny asymmetric key permissions command (action_id D class_type AK)',  # nopep8
    24245: 'Issued deny asymmetric key permissions with cascade command (action_id DWC class_type AK)',  # nopep8
    24246: 'Issued revoke asymmetric key permissions command (action_id R class_type AK)',  # nopep8
    24247: 'Issued revoke asymmetric key permissions with grant command (action_id RWG class_type AK)',  # nopep8
    24248: 'Issued revoke asymmetric key permissions with cascade command (action_id RWC class_type AK)',  # nopep8
    24249: 'Issued grant schema object permissions command (action_id G class_type OB)',  # nopep8
    24250: 'Issued grant schema object permissions with grant command (action_id GWG class_type OB)',  # nopep8
    24251: 'Issued deny schema object permissions command (action_id D class_type OB)',  # nopep8
    24252: 'Issued deny schema object permissions with cascade command (action_id DWC class_type OB)',  # nopep8
    24253: 'Issued revoke schema object permissions command (action_id R class_type OB)',  # nopep8
    24254: 'Issued revoke schema object permissions with grant command (action_id RWG class_type OB)',  # nopep8
    24255: 'Issued revoke schema object permissions with cascade command (action_id RWC class_type OB)',  # nopep8
    24256: 'Issued grant schema type permissions command (action_id G class_type TY)',  # nopep8
    24257: 'Issued grant schema type permissions with grant command (action_id GWG class_type TY)',  # nopep8
    24258: 'Issued deny schema type permissions command (action_id D class_type TY)',  # nopep8
    24259: 'Issued deny schema type permissions with cascade command (action_id DWC class_type TY)',  # nopep8
    24260: 'Issued revoke schema type permissions command (action_id R class_type TY)',  # nopep8
    24261: 'Issued revoke schema type permissions with grant command (action_id RWG class_type TY)',  # nopep8
    24262: 'Issued revoke schema type permissions with cascade command (action_id RWC class_type TY)',  # nopep8
    24263: 'Issued grant XML schema collection permissions command (action_id G class_type SX)',  # nopep8
    24264: 'Issued grant XML schema collection permissions with grant command (action_id GWG class_type SX)',  # nopep8
    24265: 'Issued deny XML schema collection permissions command (action_id D class_type SX)',  # nopep8
    24266: 'Issued deny XML schema collection permissions with cascade command (action_id DWC class_type SX)',  # nopep8
    24267: 'Issued revoke XML schema collection permissions command (action_id R class_type SX)',  # nopep8
    24268: 'Issued revoke XML schema collection permissions with grant command (action_id RWG class_type SX)',  # nopep8
    24269: 'Issued revoke XML schema collection permissions with cascade command (action_id RWC class_type SX)',  # nopep8
    24270: 'Issued reference database object permissions command (action_id RF)',  # nopep8
    24271: 'Issued send service request command (action_id SN)',
    24272: 'Issued check permissions with schema command (action_id VWCT)',
    24273: 'Issued use service broker transport security command (action_id LGB)',  # nopep8
    24274: 'Issued use database mirroring transport security command (action_id LGM)',  # nopep8
    24275: 'Issued alter trace command (action_id ALTR)',
    24276: 'Issued start trace command (action_id TASA)',
    24277: 'Issued stop trace command (action_id TASP)',
    24278: 'Issued enable trace C2 audit mode command (action_id C2ON)',
    24279: 'Issued disable trace C2 audit mode command (action_id C2OF)',
    24280: 'Issued server full-text command (action_id FT)',
    24281: 'Issued select command (action_id SL)',
    24282: 'Issued update command (action_id UP)',
    24283: 'Issued insert command (action_id IN)',
    24284: 'Issued delete command (action_id DL)',
    24285: 'Issued execute command (action_id EX)',
    24286: 'Issued receive command (action_id RC)',
    24287: 'Issued check references command (action_id RF)',
    24288: 'Issued a create user-defined server role command (action_id CR class_type SG)',  # nopep8
    24289: 'Issued a change user-defined server role command (action_id AL class_type SG)',  # nopep8
    24290: 'Issued a delete user-defined server role command (action_id DR class_type SG)',  # nopep8
    24291: 'Issued grant user-defined server role permissions command (action_id G class_type SG)',  # nopep8
    24292: 'Issued grant user-defined server role permissions with grant command (action_id GWG class_type SG)',  # nopep8
    24293: 'Issued deny user-defined server role permissions command (action_id D class_type SG)',  # nopep8
    24294: 'Issued deny user-defined server role permissions with cascade command (action_id DWC class_type SG)',  # nopep8
    24295: 'Issued revoke user-defined server role permissions command (action_id R class_type SG)',  # nopep8
    24296: 'Issued revoke user-defined server role permissions with grant command (action_id RWG class_type SG)',  # nopep8
    24297: 'Issued revoke user-defined server role permissions with cascade command (action_id RWC class_type SG)',  # nopep8
    24298: 'Database login succeeded (action_id DBAS)',
    24299: 'Database login failed (action_id DBAF)',
    24300: 'Database logout successful (action_id DAGL)',
    24301: 'Change password succeeded (action_id PWC; class_type US)',
    24302: 'Change password failed (action_id PWC; class_type US)',
    24303: 'Change own password succeeded (action_id PWCS; class_type US)',
    24304: 'Change own password failed (action_id PWCS; class_type US)',
    24305: 'Reset own password succeeded (action_id PWRS; class_type US)',
    24306: 'Reset own password failed (action_id PWRS; class_type US)',
    24307: 'Reset password succeeded (action_id PWR; class_type US)',
    24308: 'Reset password failed (action_id PWR; class_type US)',
    24309: 'Copy password (action_id USTC)',
    24310: 'User-defined SQL audit event (action_id UDAU)',
    24311: 'Issued a change database audit command (action_id AL class_type DU)',  # nopep8
    24312: 'Issued a create database audit command (action_id CR class_type DU)',  # nopep8
    24313: 'Issued a delete database audit command (action_id DR class_type DU)',  # nopep8
    24314: 'Issued a begin transaction command (action_id TXBG)',
    24315: 'Issued a commit transaction command (action_id TXCM)',
    24316: 'Issued a rollback transaction command (action_id TXRB)',
    24317: 'Issued a create column master key command (action_id CR; class_type CM)',  # nopep8
    24318: 'Issued a delete column master key command (action_id DR; class_type CM)',  # nopep8
    24319: 'A column master key was viewed (action_id VW; class_type CM)',
    24320: 'Issued a create column encryption key command (action_id CR; class_type CK)',  # nopep8
    24321: 'Issued a change column encryption key command (action_id AL; class_type CK)',  # nopep8
    24322: 'Issued a delete column encryption key command (action_id DR; class_type CK)',  # nopep8
    24323: 'A column encryption key was viewed (action_id VW; class_type CK)',
    24324: 'Issued a create database credential command (action_id CR; class_type DC)',  # nopep8
    24325: 'Issued a change database credential command (action_id AL; class_type DC)',  # nopep8
    24326: 'Issued a delete database credential command (action_id DR; class_type DC)',  # nopep8
    24327: 'Issued a change database scoped configuration command (action_id AL; class_type DS)',  # nopep8
    24328: 'Issued a create external data source command (action_id CR; class_type ED)',  # nopep8
    24329: 'Issued a change external data source command (action_id AL; class_type ED)',  # nopep8
    24330: 'Issued a delete external data source command (action_id DR; class_type ED)',  # nopep8
    24331: 'Issued a create external file format command (action_id CR; class_type EF)',  # nopep8
    24332: 'Issued a delete external file format command (action_id DR; class_type EF)',  # nopep8
    24333: 'Issued a create external resource pool command (action_id CR; class_type ER)',  # nopep8
    24334: 'Issued a change external resource pool command (action_id AL; class_type ER)',  # nopep8
    24335: 'Issued a delete external resource pool command (action_id DR; class_type ER)',  # nopep8
    24337: 'Global transaction login (action_id LGG)',
    24338: 'Grant permissions on a database scoped credential succeeded (action_id G; class_type DC)',  # nopep8
    24339: 'Grant permissions on a database scoped credential failed (action_id G; class_type DC)',  # nopep8
    24340: 'Grant permissions on a database scoped credential with grant succeeded (action_id GWG; class_type DC)',  # nopep8
    24341: 'Grant permissions on a database scoped credential with grant failed (action_id GWG; class_type DC)',  # nopep8
    24342: 'Deny permissions on a database scoped credential succeeded (action_id D; class_type DC)',  # nopep8
    24343: 'Deny permissions on a database scoped credential failed (action_id D; class_type DC)',  # nopep8
    24344: 'Deny permissions on a database scoped credential with cascade succeeded (action_id DWC; class_type DC)',  # nopep8
    24345: 'Deny permissions on a database scoped credential with cascade failed (action_id DWC; class_type DC)',  # nopep8
    24346: 'Revoke permissions on a database scoped credential succeeded (action_id R; class_type DC)',  # nopep8
    24347: 'Revoke permissions on a database scoped credential failed (action_id R; class_type DC)',  # nopep8
    24348: 'Revoke permissions with cascade on a database scoped credential succeeded (action_id RWC; class_type DC)',  # nopep8
    24349: 'Issued a change assembly owner command (action_id TO class_type AS)',  # nopep8
    24350: 'Revoke permissions with cascade on a database scoped credential failed (action_id RWC; class_type DC)',  # nopep8
    24351: 'Revoke permissions with grant on a database scoped credential succeeded (action_id RWG; class_type DC)',  # nopep8
    24352: 'Revoke permissions with grant on a database scoped credential failed (action_id RWG; class_type DC)',  # nopep8
    24353: 'Issued a change database scoped credential owner command (action_id TO; class_type DC)',  # nopep8
    24354: 'Issued a create external library command (action_id CR; class_type EL)',  # nopep8
    24355: 'Issued a change external library command (action_id AL; class_type EL)',  # nopep8
    24356: 'Issued a drop external library command (action_id DR; class_type EL)',  # nopep8
    24357: 'Grant permissions on an external library succeeded (action_id G; class_type EL)',  # nopep8
    24358: 'Grant permissions on an external library failed (action_id G; class_type EL)',  # nopep8
    24359: 'Grant permissions on an external library with grant succeeded (action_id GWG; class_type EL)',  # nopep8
    24360: 'Grant permissions on an external library with grant failed (action_id GWG; class_type EL)',  # nopep8
    24361: 'Deny permissions on an external library succeeded (action_id D; class_type EL)',  # nopep8
    24362: 'Deny permissions on an external library failed (action_id D; class_type EL)',  # nopep8
    24363: 'Deny permissions on an external library with cascade succeeded (action_id DWC; class_type EL)',  # nopep8
    24364: 'Deny permissions on an external library with cascade failed (action_id DWC; class_type EL)',  # nopep8
    24365: 'Revoke permissions on an external library succeeded (action_id R; class_type EL)',  # nopep8
    24366: 'Revoke permissions on an external library failed (action_id R; class_type EL)',  # nopep8
    24367: 'Revoke permissions with cascade on an external library succeeded (action_id RWC; class_type EL)',  # nopep8
    24368: 'Revoke permissions with cascade on an external library failed (action_id RWC; class_type EL)',  # nopep8
    24369: 'Revoke permissions with grant on an external library succeeded (action_id RWG; class_type EL)',  # nopep8
    24370: 'Revoke permissions with grant on an external library failed (action_id RWG; class_type EL)',  # nopep8
    24371: 'Issued a create database scoped resource governor command (action_id CR; class_type DR)',  # nopep8
    24372: 'Issued a change database scoped resource governor command (action_id AL; class_type DR)',  # nopep8
    24373: 'Issued a drop database scoped resource governor command (action_id DR; class_type DR)',  # nopep8
    24374: 'Issued a database bulk administration command (action_id DABO; class_type DB)',  # nopep8
    24375: 'Command to change permission failed (action_id D, DWC, G, GWG, R, RWC, RWG; class_type DC, EL)',  # nopep8
}

EXCHANGE = {
    25000: 'Undocumented Exchange mailbox operation',
    25001: 'Operation Copy - Copy item to another Exchange mailbox folder',
    25002: 'Operation Create - Create item in Exchange mailbox',
    25003: 'Operation FolderBind - Access Exchange mailbox folder',
    25004: 'Operation HardDelete - Delete Exchange mailbox item permanently from Recoverable Items folder',  # nopep8
    25005: 'Operation MessageBind - Access Exchange mailbox item',
    25006: 'Operation Move - Move item to another Exchange mailbox folder',
    25007: 'Operation MoveToDeletedItems - Move Exchange mailbox item to Deleted Items folder',  # nopep8
    25008: 'Operation SendAs - Send message using Send As Exchange mailbox permissions',  # nopep8
    25009: 'Operation SendOnBehalf - Send message using Send on Behalf Exchange mailbox permissions',  # nopep8
    25010: 'Operation SoftDelete - Delete Exchange mailbox item from Deleted Items folder',  # nopep8
    25011: 'Operation Update - Update Exchange mailbox item\'s properties',
    25100: 'Information Event - Mailbox audit policy applied',
    25100: 'Undocumented Exchange admin operation',
    25101: 'Add-ADPermission Exchange cmdlet issued',
    25102: 'Add-AvailabilityAddressSpace Exchange cmdlet issued',
    25103: 'Add-ContentFilterPhrase Exchange cmdlet issued',
    25104: 'Add-DatabaseAvailabilityGroupServer Exchange cmdlet issued',
    25105: 'Add-DistributionGroupMember Exchange cmdlet issued',
    25106: 'Add-FederatedDomain Exchange cmdlet issued',
    25107: 'Add-IPAllowListEntry Exchange cmdlet issued',
    25108: 'Add-IPAllowListProvider Exchange cmdlet issued',
    25109: 'Add-IPBlockListEntry Exchange cmdlet issued',
    25110: 'Add-IPBlockListProvider Exchange cmdlet issued',
    25111: 'Add-MailboxDatabaseCopy Exchange cmdlet issued',
    25112: 'Add-MailboxFolderPermission Exchange cmdlet issued',
    25113: 'Add-MailboxPermission Exchange cmdlet issued',
    25114: 'Add-ManagementRoleEntry Exchange cmdlet issued',
    25115: 'Add-PublicFolderAdministrativePermission Exchange cmdlet issued',
    25116: 'Add-PublicFolderClientPermission Exchange cmdlet issued',
    25117: 'Add-RoleGroupMember Exchange cmdlet issued',
    25118: 'Clean-MailboxDatabase Exchange cmdlet issued',
    25119: 'Clear-ActiveSyncDevice Exchange cmdlet issued',
    25120: 'Clear-TextMessagingAccount Exchange cmdlet issued',
    25121: 'Compare-TextMessagingVerificationCode Exchange cmdlet issued',
    25122: 'Connect-Mailbox Exchange cmdlet issued',
    25123: 'Disable-AddressListPaging Exchange cmdlet issued',
    25124: 'Disable-CmdletExtensionAgent Exchange cmdlet issued',
    25125: 'Disable-DistributionGroup Exchange cmdlet issued',
    25126: 'Disable-InboxRule Exchange cmdlet issued',
    25127: 'Disable-JournalRule Exchange cmdlet issued',
    25128: 'Disable-Mailbox Exchange cmdlet issued',
    25129: 'Disable-MailContact Exchange cmdlet issued',
    25130: 'Disable-MailPublicFolder Exchange cmdlet issued',
    25131: 'Disable-MailUser Exchange cmdlet issued',
    25132: 'Disable-OutlookAnywhere Exchange cmdlet issued',
    25133: 'Disable-OutlookProtectionRule Exchange cmdlet issued',
    25134: 'Disable-RemoteMailbox Exchange cmdlet issued',
    25135: 'Disable-ServiceEmailChannel Exchange cmdlet issued',
    25136: 'Disable-TransportAgent Exchange cmdlet issued',
    25137: 'Disable-TransportRule Exchange cmdlet issued',
    25138: 'Disable-UMAutoAttendant Exchange cmdlet issued',
    25139: 'Disable-UMIPGateway Exchange cmdlet issued',
    25140: 'Disable-UMMailbox Exchange cmdlet issued',
    25141: 'Disable-UMServer Exchange cmdlet issued',
    25142: 'Dismount-Database Exchange cmdlet issued',
    25143: 'Enable-AddressListPaging Exchange cmdlet issued',
    25144: 'Enable-AntispamUpdates Exchange cmdlet issued',
    25145: 'Enable-CmdletExtensionAgent Exchange cmdlet issued',
    25146: 'Enable-DistributionGroup Exchange cmdlet issued',
    25147: 'Enable-ExchangeCertificate Exchange cmdlet issued',
    25148: 'Enable-InboxRule Exchange cmdlet issued',
    25149: 'Enable-JournalRule Exchange cmdlet issued',
    25150: 'Enable-Mailbox Exchange cmdlet issued',
    25151: 'Enable-MailContact Exchange cmdlet issued',
    25152: 'Enable-MailPublicFolder Exchange cmdlet issued',
    25153: 'Enable-MailUser Exchange cmdlet issued',
    25154: 'Enable-OutlookAnywhere Exchange cmdlet issued',
    25155: 'Enable-OutlookProtectionRule Exchange cmdlet issued',
    25156: 'Enable-RemoteMailbox Exchange cmdlet issued',
    25157: 'Enable-ServiceEmailChannel Exchange cmdlet issued',
    25158: 'Enable-TransportAgent Exchange cmdlet issued',
    25159: 'Enable-TransportRule Exchange cmdlet issued',
    25160: 'Enable-UMAutoAttendant Exchange cmdlet issued',
    25161: 'Enable-UMIPGateway Exchange cmdlet issued',
    25162: 'Enable-UMMailbox Exchange cmdlet issued',
    25163: 'Enable-UMServer Exchange cmdlet issued',
    25164: 'Export-ActiveSyncLog Exchange cmdlet issued',
    25165: 'Export-AutoDiscoverConfig Exchange cmdlet issued',
    25166: 'Export-ExchangeCertificate Exchange cmdlet issued',
    25167: 'Export-JournalRuleCollection Exchange cmdlet issued',
    25168: 'Export-MailboxDiagnosticLogs Exchange cmdlet issued',
    25169: 'Export-Message Exchange cmdlet issued',
    25170: 'Export-RecipientDataProperty Exchange cmdlet issued',
    25171: 'Export-TransportRuleCollection Exchange cmdlet issued',
    25172: 'Export-UMCallDataRecord Exchange cmdlet issued',
    25173: 'Export-UMPrompt Exchange cmdlet issued',
    25174: 'Import-ExchangeCertificate Exchange cmdlet issued',
    25175: 'Import-JournalRuleCollection Exchange cmdlet issued',
    25176: 'Import-RecipientDataProperty Exchange cmdlet issued',
    25177: 'Import-TransportRuleCollection Exchange cmdlet issued',
    25178: 'Import-UMPrompt Exchange cmdlet issued',
    25179: 'Install-TransportAgent Exchange cmdlet issued',
    25180: 'Mount-Database Exchange cmdlet issued',
    25181: 'Move-ActiveMailboxDatabase Exchange cmdlet issued',
    25182: 'Move-AddressList Exchange cmdlet issued',
    25183: 'Move-DatabasePath Exchange cmdlet issued',
    25184: 'Move-OfflineAddressBook Exchange cmdlet issued',
    25185: 'New-AcceptedDomain Exchange cmdlet issued',
    25186: 'New-ActiveSyncDeviceAccessRule Exchange cmdlet issued',
    25187: 'New-ActiveSyncMailboxPolicy Exchange cmdlet issued',
    25188: 'New-ActiveSyncVirtualDirectory Exchange cmdlet issued',
    25189: 'New-AddressList Exchange cmdlet issued',
    25190: 'New-AdminAuditLogSearch Exchange cmdlet issued',
    25191: 'New-AutodiscoverVirtualDirectory Exchange cmdlet issued',
    25192: 'New-AvailabilityReportOutage Exchange cmdlet issued',
    25193: 'New-ClientAccessArray Exchange cmdlet issued',
    25194: 'New-DatabaseAvailabilityGroup Exchange cmdlet issued',
    25195: 'New-DatabaseAvailabilityGroupNetwork Exchange cmdlet issued',
    25196: 'New-DeliveryAgentConnector Exchange cmdlet issued',
    25197: 'New-DistributionGroup Exchange cmdlet issued',
    25198: 'New-DynamicDistributionGroup Exchange cmdlet issued',
    25199: 'New-EcpVirtualDirectory Exchange cmdlet issued',
    25200: 'New-EdgeSubscription Exchange cmdlet issued',
    25201: 'New-EdgeSyncServiceConfig Exchange cmdlet issued',
    25202: 'New-EmailAddressPolicy Exchange cmdlet issued',
    25203: 'New-ExchangeCertificate Exchange cmdlet issued',
    25204: 'New-FederationTrust Exchange cmdlet issued',
    25205: 'New-ForeignConnector Exchange cmdlet issued',
    25206: 'New-GlobalAddressList Exchange cmdlet issued',
    25207: 'New-InboxRule Exchange cmdlet issued',
    25208: 'New-JournalRule Exchange cmdlet issued',
    25209: 'New-Mailbox Exchange cmdlet issued',
    25210: 'New-MailboxAuditLogSearch Exchange cmdlet issued',
    25211: 'New-MailboxDatabase Exchange cmdlet issued',
    25212: 'New-MailboxFolder Exchange cmdlet issued',
    25213: 'New-MailboxRepairRequest Exchange cmdlet issued',
    25214: 'New-MailboxRestoreRequest Exchange cmdlet issued',
    25215: 'New-MailContact Exchange cmdlet issued',
    25216: 'New-MailMessage Exchange cmdlet issued',
    25217: 'New-MailUser Exchange cmdlet issued',
    25218: 'New-ManagedContentSettings Exchange cmdlet issued',
    25219: 'New-ManagedFolder Exchange cmdlet issued',
    25220: 'New-ManagedFolderMailboxPolicy Exchange cmdlet issued',
    25221: 'New-ManagementRole Exchange cmdlet issued',
    25222: 'New-ManagementRoleAssignment Exchange cmdlet issued',
    25223: 'New-ManagementScope Exchange cmdlet issued',
    25224: 'New-MessageClassification Exchange cmdlet issued',
    25225: 'New-MoveRequest Exchange cmdlet issued',
    25226: 'New-OabVirtualDirectory Exchange cmdlet issued',
    25227: 'New-OfflineAddressBook Exchange cmdlet issued',
    25228: 'New-OrganizationRelationship Exchange cmdlet issued',
    25229: 'New-OutlookProtectionRule Exchange cmdlet issued',
    25230: 'New-OutlookProvider Exchange cmdlet issued',
    25231: 'New-OwaMailboxPolicy Exchange cmdlet issued',
    25232: 'New-OwaVirtualDirectory Exchange cmdlet issued',
    25233: 'New-PublicFolder Exchange cmdlet issued',
    25234: 'New-PublicFolderDatabase Exchange cmdlet issued',
    25235: 'New-PublicFolderDatabaseRepairRequest Exchange cmdlet issued',
    25236: 'New-ReceiveConnector Exchange cmdlet issued',
    25237: 'New-RemoteDomain Exchange cmdlet issued',
    25238: 'New-RemoteMailbox Exchange cmdlet issued',
    25239: 'New-RetentionPolicy Exchange cmdlet issued',
    25240: 'New-RetentionPolicyTag Exchange cmdlet issued',
    25241: 'New-RoleAssignmentPolicy Exchange cmdlet issued',
    25242: 'New-RoleGroup Exchange cmdlet issued',
    25243: 'New-RoutingGroupConnector Exchange cmdlet issued',
    25244: 'New-RpcClientAccess Exchange cmdlet issued',
    25245: 'New-SendConnector Exchange cmdlet issued',
    25246: 'New-SharingPolicy Exchange cmdlet issued',
    25247: 'New-SystemMessage Exchange cmdlet issued',
    25248: 'New-ThrottlingPolicy Exchange cmdlet issued',
    25249: 'New-TransportRule Exchange cmdlet issued',
    25250: 'New-UMAutoAttendant Exchange cmdlet issued',
    25251: 'New-UMDialPlan Exchange cmdlet issued',
    25252: 'New-UMHuntGroup Exchange cmdlet issued',
    25253: 'New-UMIPGateway Exchange cmdlet issued',
    25254: 'New-UMMailboxPolicy Exchange cmdlet issued',
    25255: 'New-WebServicesVirtualDirectory Exchange cmdlet issued',
    25256: 'New-X400AuthoritativeDomain Exchange cmdlet issued',
    25257: 'Remove-AcceptedDomain Exchange cmdlet issued',
    25258: 'Remove-ActiveSyncDevice Exchange cmdlet issued',
    25259: 'Remove-ActiveSyncDeviceAccessRule Exchange cmdlet issued',
    25260: 'Remove-ActiveSyncDeviceClass Exchange cmdlet issued',
    25261: 'Remove-ActiveSyncMailboxPolicy Exchange cmdlet issued',
    25262: 'Remove-ActiveSyncVirtualDirectory Exchange cmdlet issued',
    25263: 'Remove-AddressList Exchange cmdlet issued',
    25264: 'Remove-ADPermission Exchange cmdlet issued',
    25265: 'Remove-AutodiscoverVirtualDirectory Exchange cmdlet issued',
    25266: 'Remove-AvailabilityAddressSpace Exchange cmdlet issued',
    25267: 'Remove-AvailabilityReportOutage Exchange cmdlet issued',
    25268: 'Remove-ClientAccessArray Exchange cmdlet issued',
    25269: 'Remove-ContentFilterPhrase Exchange cmdlet issued',
    25270: 'Remove-DatabaseAvailabilityGroup Exchange cmdlet issued',
    25271: 'Remove-DatabaseAvailabilityGroupNetwork Exchange cmdlet issued',
    25272: 'Remove-DatabaseAvailabilityGroupServer Exchange cmdlet issued',
    25273: 'Remove-DeliveryAgentConnector Exchange cmdlet issued',
    25274: 'Remove-DistributionGroup Exchange cmdlet issued',
    25275: 'Remove-DistributionGroupMember Exchange cmdlet issued',
    25276: 'Remove-DynamicDistributionGroup Exchange cmdlet issued',
    25277: 'Remove-EcpVirtualDirectory Exchange cmdlet issued',
    25278: 'Remove-EdgeSubscription Exchange cmdlet issued',
    25279: 'Remove-EmailAddressPolicy Exchange cmdlet issued',
    25280: 'Remove-ExchangeCertificate Exchange cmdlet issued',
    25281: 'Remove-FederatedDomain Exchange cmdlet issued',
    25282: 'Remove-FederationTrust Exchange cmdlet issued',
    25283: 'Remove-ForeignConnector Exchange cmdlet issued',
    25284: 'Remove-GlobalAddressList Exchange cmdlet issued',
    25285: 'Remove-InboxRule Exchange cmdlet issued',
    25286: 'Remove-IPAllowListEntry Exchange cmdlet issued',
    25287: 'Remove-IPAllowListProvider Exchange cmdlet issued',
    25288: 'Remove-IPBlockListEntry Exchange cmdlet issued',
    25289: 'Remove-IPBlockListProvider Exchange cmdlet issued',
    25290: 'Remove-JournalRule Exchange cmdlet issued',
    25291: 'Remove-Mailbox Exchange cmdlet issued',
    25292: 'Remove-MailboxDatabase Exchange cmdlet issued',
    25293: 'Remove-MailboxDatabaseCopy Exchange cmdlet issued',
    25294: 'Remove-MailboxFolderPermission Exchange cmdlet issued',
    25295: 'Remove-MailboxPermission Exchange cmdlet issued',
    25296: 'Remove-MailboxRestoreRequest Exchange cmdlet issued',
    25297: 'Remove-MailContact Exchange cmdlet issued',
    25298: 'Remove-MailUser Exchange cmdlet issued',
    25299: 'Remove-ManagedContentSettings Exchange cmdlet issued',
    25300: 'Remove-ManagedFolder Exchange cmdlet issued',
    25301: 'Remove-ManagedFolderMailboxPolicy Exchange cmdlet issued',
    25302: 'Remove-ManagementRole Exchange cmdlet issued',
    25303: 'Remove-ManagementRoleAssignment Exchange cmdlet issued',
    25304: 'Remove-ManagementRoleEntry Exchange cmdlet issued',
    25305: 'Remove-ManagementScope Exchange cmdlet issued',
    25306: 'Remove-Message Exchange cmdlet issued',
    25307: 'Remove-MessageClassification Exchange cmdlet issued',
    25308: 'Remove-MoveRequest Exchange cmdlet issued',
    25309: 'Remove-OabVirtualDirectory Exchange cmdlet issued',
    25310: 'Remove-OfflineAddressBook Exchange cmdlet issued',
    25311: 'Remove-OrganizationRelationship Exchange cmdlet issued',
    25312: 'Remove-OutlookProtectionRule Exchange cmdlet issued',
    25313: 'Remove-OutlookProvider Exchange cmdlet issued',
    25314: 'Remove-OwaMailboxPolicy Exchange cmdlet issued',
    25315: 'Remove-OwaVirtualDirectory Exchange cmdlet issued',
    25316: 'Remove-PublicFolder Exchange cmdlet issued',
    25317: 'Remove-PublicFolderAdministrativePermission Exchange cmdlet issued',  # nopep8
    25318: 'Remove-PublicFolderClientPermission Exchange cmdlet issued',
    25319: 'Remove-PublicFolderDatabase Exchange cmdlet issued',
    25320: 'Remove-ReceiveConnector Exchange cmdlet issued',
    25321: 'Remove-RemoteDomain Exchange cmdlet issued',
    25322: 'Remove-RemoteMailbox Exchange cmdlet issued',
    25323: 'Remove-RetentionPolicy Exchange cmdlet issued',
    25324: 'Remove-RetentionPolicyTag Exchange cmdlet issued',
    25325: 'Remove-RoleAssignmentPolicy Exchange cmdlet issued',
    25326: 'Remove-RoleGroup Exchange cmdlet issued',
    25327: 'Remove-RoleGroupMember Exchange cmdlet issued',
    25328: 'Remove-RoutingGroupConnector Exchange cmdlet issued',
    25329: 'Remove-RpcClientAccess Exchange cmdlet issued',
    25330: 'Remove-SendConnector Exchange cmdlet issued',
    25331: 'Remove-SharingPolicy Exchange cmdlet issued',
    25332: 'Remove-StoreMailbox Exchange cmdlet issued',
    25333: 'Remove-SystemMessage Exchange cmdlet issued',
    25334: 'Remove-ThrottlingPolicy Exchange cmdlet issued',
    25335: 'Remove-TransportRule Exchange cmdlet issued',
    25336: 'Remove-UMAutoAttendant Exchange cmdlet issued',
    25337: 'Remove-UMDialPlan Exchange cmdlet issued',
    25338: 'Remove-UMHuntGroup Exchange cmdlet issued',
    25339: 'Remove-UMIPGateway Exchange cmdlet issued',
    25340: 'Remove-UMMailboxPolicy Exchange cmdlet issued',
    25341: 'Remove-WebServicesVirtualDirectory Exchange cmdlet issued',
    25342: 'Remove-X400AuthoritativeDomain Exchange cmdlet issued',
    25343: 'Restore-DatabaseAvailabilityGroup Exchange cmdlet issued',
    25344: 'Restore-DetailsTemplate Exchange cmdlet issued',
    25345: 'Restore-Mailbox Exchange cmdlet issued',
    25346: 'Resume-MailboxDatabaseCopy Exchange cmdlet issued',
    25347: 'Resume-MailboxExportRequest Exchange cmdlet issued',
    25348: 'Resume-MailboxRestoreRequest Exchange cmdlet issued',
    25349: 'Resume-Message Exchange cmdlet issued',
    25350: 'Resume-MoveRequest Exchange cmdlet issued',
    25351: 'Resume-PublicFolderReplication Exchange cmdlet issued',
    25352: 'Resume-Queue Exchange cmdlet issued',
    25353: 'Retry-Queue Exchange cmdlet issued',
    25354: 'Send-TextMessagingVerificationCode Exchange cmdlet issued',
    25355: 'Set-AcceptedDomain Exchange cmdlet issued',
    25356: 'Set-ActiveSyncDeviceAccessRule Exchange cmdlet issued',
    25357: 'Set-ActiveSyncMailboxPolicy Exchange cmdlet issued',
    25358: 'Set-ActiveSyncOrganizationSettings Exchange cmdlet issued',
    25359: 'Set-ActiveSyncVirtualDirectory Exchange cmdlet issued',
    25360: 'Set-AddressList Exchange cmdlet issued',
    25361: 'Set-AdminAuditLogConfig Exchange cmdlet issued',
    25362: 'Set-ADServerSettings Exchange cmdlet issued',
    25363: 'Set-ADSite Exchange cmdlet issued',
    25364: 'Set-AdSiteLink Exchange cmdlet issued',
    25365: 'Set-AutodiscoverVirtualDirectory Exchange cmdlet issued',
    25366: 'Set-AvailabilityConfig Exchange cmdlet issued',
    25367: 'Set-AvailabilityReportOutage Exchange cmdlet issued',
    25368: 'Set-CalendarNotification Exchange cmdlet issued',
    25369: 'Set-CalendarProcessing Exchange cmdlet issued',
    25370: 'Set-CASMailbox Exchange cmdlet issued',
    25371: 'Set-ClientAccessArray Exchange cmdlet issued',
    25372: 'Set-ClientAccessServer Exchange cmdlet issued',
    25373: 'Set-CmdletExtensionAgent Exchange cmdlet issued',
    25374: 'Set-Contact Exchange cmdlet issued',
    25375: 'Set-ContentFilterConfig Exchange cmdlet issued',
    25376: 'Set-DatabaseAvailabilityGroup Exchange cmdlet issued',
    25377: 'Set-DatabaseAvailabilityGroupNetwork Exchange cmdlet issued',
    25378: 'Set-DeliveryAgentConnector Exchange cmdlet issued',
    25379: 'Set-DetailsTemplate Exchange cmdlet issued',
    25380: 'Set-DistributionGroup Exchange cmdlet issued',
    25381: 'Set-DynamicDistributionGroup Exchange cmdlet issued',
    25382: 'Set-EcpVirtualDirectory Exchange cmdlet issued',
    25383: 'Set-EdgeSyncServiceConfig Exchange cmdlet issued',
    25384: 'Set-EmailAddressPolicy Exchange cmdlet issued',
    25385: 'Set-EventLogLevel Exchange cmdlet issued',
    25386: 'Set-ExchangeAssistanceConfig Exchange cmdlet issued',
    25387: 'Set-ExchangeServer Exchange cmdlet issued',
    25388: 'Set-FederatedOrganizationIdentifier Exchange cmdlet issued',
    25389: 'Set-FederationTrust Exchange cmdlet issued',
    25390: 'Set-ForeignConnector Exchange cmdlet issued',
    25391: 'Set-GlobalAddressList Exchange cmdlet issued',
    25392: 'Set-Group Exchange cmdlet issued',
    25393: 'Set-ImapSettings Exchange cmdlet issued',
    25394: 'Set-InboxRule Exchange cmdlet issued',
    25395: 'Set-IPAllowListConfig Exchange cmdlet issued',
    25396: 'Set-IPAllowListProvider Exchange cmdlet issued',
    25397: 'Set-IPAllowListProvidersConfig Exchange cmdlet issued',
    25398: 'Set-IPBlockListConfig Exchange cmdlet issued',
    25399: 'Set-IPBlockListProvider Exchange cmdlet issued',
    25400: 'Set-IPBlockListProvidersConfig Exchange cmdlet issued',
    25401: 'Set-IRMConfiguration Exchange cmdlet issued',
    25402: 'Set-JournalRule Exchange cmdlet issued',
    25403: 'Set-Mailbox Exchange cmdlet issued',
    25404: 'Set-MailboxAuditBypassAssociation Exchange cmdlet issued',
    25405: 'Set-MailboxAutoReplyConfiguration Exchange cmdlet issued',
    25406: 'Set-MailboxCalendarConfiguration Exchange cmdlet issued',
    25407: 'Set-MailboxCalendarFolder Exchange cmdlet issued',
    25408: 'Set-MailboxDatabase Exchange cmdlet issued',
    25409: 'Set-MailboxDatabaseCopy Exchange cmdlet issued',
    25410: 'Set-MailboxFolderPermission Exchange cmdlet issued',
    25411: 'Set-MailboxJunkEmailConfiguration Exchange cmdlet issued',
    25412: 'Set-MailboxMessageConfiguration Exchange cmdlet issued',
    25413: 'Set-MailboxRegionalConfiguration Exchange cmdlet issued',
    25414: 'Set-MailboxRestoreRequest Exchange cmdlet issued',
    25415: 'Set-MailboxServer Exchange cmdlet issued',
    25416: 'Set-MailboxSpellingConfiguration Exchange cmdlet issued',
    25417: 'Set-MailContact Exchange cmdlet issued',
    25418: 'Set-MailPublicFolder Exchange cmdlet issued',
    25419: 'Set-MailUser Exchange cmdlet issued',
    25420: 'Set-ManagedContentSettings Exchange cmdlet issued',
    25421: 'Set-ManagedFolder Exchange cmdlet issued',
    25422: 'Set-ManagedFolderMailboxPolicy Exchange cmdlet issued',
    25423: 'Set-ManagementRoleAssignment Exchange cmdlet issued',
    25424: 'Set-ManagementRoleEntry Exchange cmdlet issued',
    25425: 'Set-ManagementScope Exchange cmdlet issued',
    25426: 'Set-MessageClassification Exchange cmdlet issued',
    25427: 'Set-MoveRequest Exchange cmdlet issued',
    25428: 'Set-OabVirtualDirectory Exchange cmdlet issued',
    25429: 'Set-OfflineAddressBook Exchange cmdlet issued',
    25430: 'Set-OrganizationConfig Exchange cmdlet issued',
    25431: 'Set-OrganizationRelationship Exchange cmdlet issued',
    25432: 'Set-OutlookAnywhere Exchange cmdlet issued',
    25433: 'Set-OutlookProtectionRule Exchange cmdlet issued',
    25434: 'Set-OutlookProvider Exchange cmdlet issued',
    25435: 'Set-OwaMailboxPolicy Exchange cmdlet issued',
    25436: 'Set-OwaVirtualDirectory Exchange cmdlet issued',
    25437: 'Set-PopSettings Exchange cmdlet issued',
    25438: 'Set-PowerShellVirtualDirectory Exchange cmdlet issued',
    25439: 'Set-PublicFolder Exchange cmdlet issued',
    25440: 'Set-PublicFolderDatabase Exchange cmdlet issued',
    25441: 'Set-ReceiveConnector Exchange cmdlet issued',
    25442: 'Set-RecipientFilterConfig Exchange cmdlet issued',
    25443: 'Set-RemoteDomain Exchange cmdlet issued',
    25444: 'Set-RemoteMailbox Exchange cmdlet issued',
    25445: 'Set-ResourceConfig Exchange cmdlet issued',
    25446: 'Set-RetentionPolicy Exchange cmdlet issued',
    25447: 'Set-RetentionPolicyTag Exchange cmdlet issued',
    25448: 'Set-RoleAssignmentPolicy Exchange cmdlet issued',
    25449: 'Set-RoleGroup Exchange cmdlet issued',
    25450: 'Set-RoutingGroupConnector Exchange cmdlet issued',
    25451: 'Set-RpcClientAccess Exchange cmdlet issued',
    25452: 'Set-SendConnector Exchange cmdlet issued',
    25453: 'Set-SenderFilterConfig Exchange cmdlet issued',
    25454: 'Set-SenderIdConfig Exchange cmdlet issued',
    25455: 'Set-SenderReputationConfig Exchange cmdlet issued',
    25456: 'Set-SharingPolicy Exchange cmdlet issued',
    25457: 'Set-SystemMessage Exchange cmdlet issued',
    25458: 'Set-TextMessagingAccount Exchange cmdlet issued',
    25459: 'Set-ThrottlingPolicy Exchange cmdlet issued',
    25460: 'Set-ThrottlingPolicyAssociation Exchange cmdlet issued',
    25461: 'Set-TransportAgent Exchange cmdlet issued',
    25462: 'Set-TransportConfig Exchange cmdlet issued',
    25463: 'Set-TransportRule Exchange cmdlet issued',
    25464: 'Set-TransportServer Exchange cmdlet issued',
    25465: 'Set-UMAutoAttendant Exchange cmdlet issued',
    25466: 'Set-UMDialPlan Exchange cmdlet issued',
    25467: 'Set-UMIPGateway Exchange cmdlet issued',
    25468: 'Set-UMMailbox Exchange cmdlet issued',
    25469: 'Set-UMMailboxPIN Exchange cmdlet issued',
    25470: 'Set-UMMailboxPolicy Exchange cmdlet issued',
    25471: 'Set-UmServer Exchange cmdlet issued',
    25472: 'Set-User Exchange cmdlet issued',
    25473: 'Set-WebServicesVirtualDirectory Exchange cmdlet issued',
    25474: 'Set-X400AuthoritativeDomain Exchange cmdlet issued',
    25475: 'Start-DatabaseAvailabilityGroup Exchange cmdlet issued',
    25476: 'Start-EdgeSynchronization Exchange cmdlet issued',
    25477: 'Start-ManagedFolderAssistant Exchange cmdlet issued',
    25478: 'Start-RetentionAutoTagLearning Exchange cmdlet issued',
    25479: 'Stop-DatabaseAvailabilityGroup Exchange cmdlet issued',
    25480: 'Stop-ManagedFolderAssistant Exchange cmdlet issued',
    25481: 'Suspend-MailboxDatabaseCopy Exchange cmdlet issued',
    25482: 'Suspend-MailboxRestoreRequest Exchange cmdlet issued',
    25483: 'Suspend-Message Exchange cmdlet issued',
    25484: 'Suspend-MoveRequest Exchange cmdlet issued',
    25485: 'Suspend-PublicFolderReplication Exchange cmdlet issued',
    25486: 'Suspend-Queue Exchange cmdlet issued',
    25487: 'Test-ActiveSyncConnectivity Exchange cmdlet issued',
    25488: 'Test-AssistantHealth Exchange cmdlet issued',
    25489: 'Test-CalendarConnectivity Exchange cmdlet issued',
    25490: 'Test-EcpConnectivity Exchange cmdlet issued',
    25491: 'Test-EdgeSynchronization Exchange cmdlet issued',
    25492: 'Test-ExchangeSearch Exchange cmdlet issued',
    25493: 'Test-FederationTrust Exchange cmdlet issued',
    25494: 'Test-FederationTrustCertificate Exchange cmdlet issued',
    25495: 'Test-ImapConnectivity Exchange cmdlet issued',
    25496: 'Test-IPAllowListProvider Exchange cmdlet issued',
    25497: 'Test-IPBlockListProvider Exchange cmdlet issued',
    25498: 'Test-IRMConfiguration Exchange cmdlet issued',
    25499: 'Test-Mailflow Exchange cmdlet issued',
    25500: 'Test-MAPIConnectivity Exchange cmdlet issued',
    25501: 'Test-MRSHealth Exchange cmdlet issued',
    25502: 'Test-OrganizationRelationship Exchange cmdlet issued',
    25503: 'Test-OutlookConnectivity Exchange cmdlet issued',
    25504: 'Test-OutlookWebServices Exchange cmdlet issued',
    25505: 'Test-OwaConnectivity Exchange cmdlet issued',
    25506: 'Test-PopConnectivity Exchange cmdlet issued',
    25507: 'Test-PowerShellConnectivity Exchange cmdlet issued',
    25508: 'Test-ReplicationHealth Exchange cmdlet issued',
    25509: 'Test-SenderId Exchange cmdlet issued',
    25510: 'Test-ServiceHealth Exchange cmdlet issued',
    25511: 'Test-SmtpConnectivity Exchange cmdlet issued',
    25512: 'Test-SystemHealth Exchange cmdlet issued',
    25513: 'Test-UMConnectivity Exchange cmdlet issued',
    25514: 'Test-WebServicesConnectivity Exchange cmdlet issued',
    25515: 'Uninstall-TransportAgent Exchange cmdlet issued',
    25516: 'Update-AddressList Exchange cmdlet issued',
    25517: 'Update-DistributionGroupMember Exchange cmdlet issued',
    25518: 'Update-EmailAddressPolicy Exchange cmdlet issued',
    25519: 'Update-FileDistributionService Exchange cmdlet issued',
    25520: 'Update-GlobalAddressList Exchange cmdlet issued',
    25521: 'Update-MailboxDatabaseCopy Exchange cmdlet issued',
    25522: 'Update-OfflineAddressBook Exchange cmdlet issued',
    25523: 'Update-PublicFolder Exchange cmdlet issued',
    25524: 'Update-PublicFolderHierarchy Exchange cmdlet issued',
    25525: 'Update-Recipient Exchange cmdlet issued',
    25526: 'Update-RoleGroupMember Exchange cmdlet issued',
    25527: 'Update-SafeList Exchange cmdlet issued',
    25528: 'Write-AdminAuditLog Exchange cmdlet issued',
    25529: 'Add-GlobalMonitoringOverride Exchange cmdlet issued',
    25530: 'Add-ResubmitRequest Exchange cmdlet issued',
    25531: 'Add-ServerMonitoringOverride Exchange cmdlet issued',
    25532: 'Clear-MobileDevice Exchange cmdlet issued',
    25533: 'Complete-MigrationBatch Exchange cmdlet issued',
    25534: 'Disable-App Exchange cmdlet issued',
    25535: 'Disable-MailboxQuarantine Exchange cmdlet issued',
    25536: 'Disable-UMCallAnsweringRule Exchange cmdlet issued',
    25537: 'Disable-UMService Exchange cmdlet issued',
    25538: 'Dump-ProvisioningCache Exchange cmdlet issued',
    25539: 'Enable-App Exchange cmdlet issued',
    25540: 'Enable-MailboxQuarantine Exchange cmdlet issued',
    25541: 'Enable-UMCallAnsweringRule Exchange cmdlet issued',
    25542: 'Enable-UMService Exchange cmdlet issued',
    25543: 'Export-DlpPolicyCollection Exchange cmdlet issued',
    25544: 'Export-MigrationReport Exchange cmdlet issued',
    25545: 'Import-DlpPolicyCollection Exchange cmdlet issued',
    25546: 'Import-DlpPolicyTemplate Exchange cmdlet issued',
    25547: 'Invoke-MonitoringProbe Exchange cmdlet issued',
    25548: 'New-AddressBookPolicy Exchange cmdlet issued',
    25549: 'New-App Exchange cmdlet issued',
    25550: 'New-AuthServer Exchange cmdlet issued',
    25551: 'New-ClassificationRuleCollection Exchange cmdlet issued',
    25552: 'New-DlpPolicy Exchange cmdlet issued',
    25553: 'New-HybridConfiguration Exchange cmdlet issued',
    25554: 'New-MailboxExportRequest Exchange cmdlet issued',
    25555: 'New-MailboxImportRequest Exchange cmdlet issued',
    25556: 'New-MailboxSearch Exchange cmdlet issued',
    25557: 'New-MalwareFilterPolicy Exchange cmdlet issued',
    25558: 'New-MigrationBatch Exchange cmdlet issued',
    25559: 'New-MigrationEndpoint Exchange cmdlet issued',
    25560: 'New-MobileDeviceMailboxPolicy Exchange cmdlet issued',
    25561: 'New-OnPremisesOrganization Exchange cmdlet issued',
    25562: 'New-PartnerApplication Exchange cmdlet issued',
    25563: 'New-PolicyTipConfig Exchange cmdlet issued',
    25564: 'New-PowerShellVirtualDirectory Exchange cmdlet issued',
    25565: 'New-PublicFolderMigrationRequest Exchange cmdlet issued',
    25566: 'New-ResourcePolicy Exchange cmdlet issued',
    25567: 'New-SiteMailboxProvisioningPolicy Exchange cmdlet issued',
    25568: 'New-SyncMailPublicFolder Exchange cmdlet issued',
    25569: 'New-UMCallAnsweringRule Exchange cmdlet issued',
    25570: 'New-WorkloadManagementPolicy Exchange cmdlet issued',
    25571: 'New-WorkloadPolicy Exchange cmdlet issued',
    25572: 'Redirect-Message Exchange cmdlet issued',
    25573: 'Remove-AddressBookPolicy Exchange cmdlet issued',
    25574: 'Remove-App Exchange cmdlet issued',
    25575: 'Remove-AuthServer Exchange cmdlet issued',
    25576: 'Remove-ClassificationRuleCollection Exchange cmdlet issued',
    25577: 'Remove-DlpPolicy Exchange cmdlet issued',
    25578: 'Remove-DlpPolicyTemplate Exchange cmdlet issued',
    25579: 'Remove-GlobalMonitoringOverride Exchange cmdlet issued',
    25580: 'Remove-HybridConfiguration Exchange cmdlet issued',
    25581: 'Remove-LinkedUser Exchange cmdlet issued',
    25582: 'Remove-MailboxExportRequest Exchange cmdlet issued',
    25583: 'Remove-MailboxImportRequest Exchange cmdlet issued',
    25584: 'Remove-MailboxSearch Exchange cmdlet issued',
    25585: 'Remove-MalwareFilterPolicy Exchange cmdlet issued',
    25586: 'Remove-MalwareFilterRecoveryItem Exchange cmdlet issued',
    25587: 'Remove-MigrationBatch Exchange cmdlet issued',
    25588: 'Remove-MigrationEndpoint Exchange cmdlet issued',
    25589: 'Remove-MigrationUser Exchange cmdlet issued',
    25590: 'Remove-MobileDevice Exchange cmdlet issued',
    25591: 'Remove-MobileDeviceMailboxPolicy Exchange cmdlet issued',
    25592: 'Remove-OnPremisesOrganization Exchange cmdlet issued',
    25593: 'Remove-PartnerApplication Exchange cmdlet issued',
    25594: 'Remove-PolicyTipConfig Exchange cmdlet issued',
    25595: 'Remove-PowerShellVirtualDirectory Exchange cmdlet issued',
    25596: 'Remove-PublicFolderMigrationRequest Exchange cmdlet issued',
    25597: 'Remove-ResourcePolicy Exchange cmdlet issued',
    25598: 'Remove-ResubmitRequest Exchange cmdlet issued',
    25599: 'Remove-SiteMailboxProvisioningPolicy Exchange cmdlet issued',
    25600: 'Remove-UMCallAnsweringRule Exchange cmdlet issued',
    25601: 'Remove-UserPhoto Exchange cmdlet issued',
    25602: 'Remove-WorkloadManagementPolicy Exchange cmdlet issued',
    25603: 'Remove-WorkloadPolicy Exchange cmdlet issued',
    25604: 'Reset-ProvisioningCache Exchange cmdlet issued',
    25605: 'Resume-MailboxImportRequest Exchange cmdlet issued',
    25606: 'Resume-MalwareFilterRecoveryItem Exchange cmdlet issued',
    25607: 'Resume-PublicFolderMigrationRequest Exchange cmdlet issued',
    25608: 'Set-ActiveSyncDeviceAccessRule Exchange cmdlet issued',
    25609: 'Set-AddressBookPolicy Exchange cmdlet issued',
    25610: 'Set-App Exchange cmdlet issued',
    25611: 'Set-AuthConfig Exchange cmdlet issued',
    25612: 'Set-AuthServer Exchange cmdlet issued',
    25613: 'Set-ClassificationRuleCollection Exchange cmdlet issued',
    25614: 'Set-DlpPolicy Exchange cmdlet issued',
    25615: 'Set-FrontendTransportService Exchange cmdlet issued',
    25616: 'Set-HybridConfiguration Exchange cmdlet issued',
    25617: 'Set-HybridMailflow Exchange cmdlet issued',
    25618: 'Set-MailboxExportRequest Exchange cmdlet issued',
    25619: 'Set-MailboxImportRequest Exchange cmdlet issued',
    25620: 'Set-MailboxSearch Exchange cmdlet issued',
    25621: 'Set-MailboxTransportService Exchange cmdlet issued',
    25622: 'Set-MalwareFilteringServer Exchange cmdlet issued',
    25623: 'Set-MalwareFilterPolicy Exchange cmdlet issued',
    25624: 'Set-MigrationBatch Exchange cmdlet issued',
    25625: 'Set-MigrationConfig Exchange cmdlet issued',
    25626: 'Set-MigrationEndpoint Exchange cmdlet issued',
    25627: 'Set-MobileDeviceMailboxPolicy Exchange cmdlet issued',
    25628: 'Set-Notification Exchange cmdlet issued',
    25629: 'Set-OnPremisesOrganization Exchange cmdlet issued',
    25630: 'Set-PartnerApplication Exchange cmdlet issued',
    25631: 'Set-PendingFederatedDomain Exchange cmdlet issued',
    25632: 'Set-PolicyTipConfig Exchange cmdlet issued',
    25633: 'Set-PublicFolderMigrationRequest Exchange cmdlet issued',
    25634: 'Set-ResourcePolicy Exchange cmdlet issued',
    25635: 'Set-ResubmitRequest Exchange cmdlet issued',
    25636: 'Set-RMSTemplate Exchange cmdlet issued',
    25637: 'Set-ServerComponentState Exchange cmdlet issued',
    25638: 'Set-ServerMonitor Exchange cmdlet issued',
    25639: 'Set-SiteMailbox Exchange cmdlet issued',
    25640: 'Set-SiteMailboxProvisioningPolicy Exchange cmdlet issued',
    25641: 'Set-TransportService Exchange cmdlet issued',
    25642: 'Set-UMCallAnsweringRule Exchange cmdlet issued',
    25643: 'Set-UMCallRouterSettings Exchange cmdlet issued',
    25644: 'Set-UMService Exchange cmdlet issued',
    25645: 'Set-UserPhoto Exchange cmdlet issued',
    25646: 'Set-WorkloadPolicy Exchange cmdlet issued',
    25647: 'Start-MailboxSearch Exchange cmdlet issued',
    25648: 'Start-MigrationBatch Exchange cmdlet issued',
    25649: 'Stop-MailboxSearch Exchange cmdlet issued',
    25650: 'Stop-MigrationBatch Exchange cmdlet issued',
    25651: 'Suspend-MailboxExportRequest Exchange cmdlet issued',
    25652: 'Suspend-MailboxImportRequest Exchange cmdlet issued',
    25653: 'Suspend-PublicFolderMigrationRequest Exchange cmdlet issued',
    25654: 'Test-ArchiveConnectivity Exchange cmdlet issued',
    25655: 'Test-MigrationServerAvailability Exchange cmdlet issued',
    25656: 'Test-OAuthConnectivity Exchange cmdlet issued',
    25657: 'Test-SiteMailbox Exchange cmdlet issued',
    25658: 'Update-HybridConfiguration Exchange cmdlet issued',
    25659: 'Update-PublicFolderMailbox Exchange cmdlet issued',
    25660: 'Update-SiteMailbox Exchange cmdlet issued',
    25661: 'Add-AttachmentFilterEntry Exchange cmdlet issued',
    25662: 'Remove-AttachmentFilterEntry Exchange cmdlet issued',
    25663: 'New-AddressRewriteEntry Exchange cmdlet issued',
    25664: 'Remove-AddressRewriteEntry Exchange cmdlet issued',
    25665: 'Set-AddressRewriteEntry Exchange cmdlet issued',
    25666: 'Set-AttachmentFilterListConfig Exchange cmdlet issued',
    25667: 'Set-MailboxSentItemsConfiguration Exchange cmdlet issued',
    25668: 'Update-MovedMailbox Exchange cmdlet issued',
    25669: 'Disable-MalwareFilterRule Exchange cmdlet issued',
    25670: 'Enable-MalwareFilterRule Exchange cmdlet issued',
    25671: 'New-MalwareFilterRule Exchange cmdlet issued',
    25672: 'Remove-MalwareFilterRule Exchange cmdlet issued',
    25673: 'Set-MalwareFilterRule Exchange cmdlet issued',
    25674: 'Remove-MailboxRepairRequest Exchange cmdlet issued',
    25675: 'Remove-ServerMonitoringOverride Exchange cmdlet issued',
    25676: 'Update-ExchangeHelp Exchange cmdlet issued',
    25677: 'Update-StoreMailboxState Exchange cmdlet issued',
    25678: 'Disable-PushNotificationProxy Exchange cmdlet issued',
    25679: 'Enable-PushNotificationProxy Exchange cmdlet issued',
    25680: 'New-PublicFolderMoveRequest Exchange cmdlet issued',
    25681: 'Remove-PublicFolderMoveRequest Exchange cmdlet issued',
    25682: 'Resume-PublicFolderMoveRequest Exchange cmdlet issued',
    25683: 'Set-PublicFolderMoveRequest Exchange cmdlet issued',
    25684: 'Suspend-PublicFolderMoveRequest Exchange cmdlet issued',
    25685: 'Update-DatabaseSchema Exchange cmdlet issued',
    25686: 'Set-SearchDocumentFormat Exchange cmdlet issued',
    25687: 'New-AuthRedirect Exchange cmdlet issued',
    25688: 'New-CompliancePolicySyncNotification Exchange cmdlet issued',
    25689: 'New-ComplianceServiceVirtualDirectory Exchange cmdlet issued',
    25690: 'New-DatabaseAvailabilityGroupConfiguration Exchange cmdlet issued',
    25691: 'New-DataClassification Exchange cmdlet issued',
    25692: 'New-Fingerprint Exchange cmdlet issued',
    25693: 'New-IntraOrganizationConnector Exchange cmdlet issued',
    25694: 'New-MailboxDeliveryVirtualDirectory Exchange cmdlet issued',
    25695: 'New-MapiVirtualDirectory Exchange cmdlet issued',
    25696: 'New-OutlookServiceVirtualDirectory Exchange cmdlet issued',
    25697: 'New-RestVirtualDirectory Exchange cmdlet issued',
    25698: 'New-SearchDocumentFormat Exchange cmdlet issued',
    25699: 'New-SettingOverride Exchange cmdlet issued',
    25700: 'New-SiteMailbox Exchange cmdlet issued',
    25701: 'Remove-AuthRedirect Exchange cmdlet issued',
    25702: 'Remove-CompliancePolicySyncNotification Exchange cmdlet issued',
    25703: 'Remove-ComplianceServiceVirtualDirectory Exchange cmdlet issued',
    25704: 'Remove-DatabaseAvailabilityGroupConfiguration Exchange cmdlet issued',  # nopep8
    25705: 'Remove-DataClassification Exchange cmdlet issued',
    25706: 'Remove-IntraOrganizationConnector Exchange cmdlet issued',
    25707: 'Remove-MailboxDeliveryVirtualDirectory Exchange cmdlet issued',
    25708: 'Remove-MapiVirtualDirectory Exchange cmdlet issued',
    25709: 'Remove-OutlookServiceVirtualDirectory Exchange cmdlet issued',
    25710: 'Remove-PublicFolderMailboxMigrationRequest Exchange cmdlet issued',
    25711: 'Remove-PushNotificationSubscription Exchange cmdlet issued',
    25712: 'Remove-RestVirtualDirectory Exchange cmdlet issued',
    25713: 'Remove-SearchDocumentFormat Exchange cmdlet issued',
    25714: 'Remove-SettingOverride Exchange cmdlet issued',
    25715: 'Remove-SyncMailPublicFolder Exchange cmdlet issued',
    25716: 'Resume-PublicFolderMailboxMigrationRequest Exchange cmdlet issued',
    25717: 'Send-MapiSubmitSystemProbe Exchange cmdlet issued',
    25718: 'Set-AuthRedirect Exchange cmdlet issued',
    25719: 'Set-ClientAccessService Exchange cmdlet issued',
    25720: 'Set-Clutter Exchange cmdlet issued',
    25721: 'Set-ComplianceServiceVirtualDirectory Exchange cmdlet issued',
    25722: 'Set-ConsumerMailbox Exchange cmdlet issued',
    25723: 'Set-DatabaseAvailabilityGroupConfiguration Exchange cmdlet issued',
    25724: 'Set-DataClassification Exchange cmdlet issued',
    25725: 'Set-IntraOrganizationConnector Exchange cmdlet issued',
    25726: 'Set-LogExportVirtualDirectory Exchange cmdlet issued',
    25727: 'Set-MailboxDeliveryVirtualDirectory Exchange cmdlet issued',
    25728: 'Set-MapiVirtualDirectory Exchange cmdlet issued',
    25729: 'Set-OutlookServiceVirtualDirectory Exchange cmdlet issued',
    25730: 'Set-PublicFolderMailboxMigrationRequest Exchange cmdlet issued',
    25731: 'Set-RestVirtualDirectory Exchange cmdlet issued',
    25732: 'Set-SettingOverride Exchange cmdlet issued',
    25733: 'Set-SmimeConfig Exchange cmdlet issued',
    25734: 'Set-SubmissionMalwareFilteringServer Exchange cmdlet issued',
    25735: 'Set-UMMailboxConfiguration Exchange cmdlet issued',
    25736: 'Set-UnifiedAuditSetting Exchange cmdlet issued',
    25737: 'Start-AuditAssistant Exchange cmdlet issued',
    25738: 'Start-UMPhoneSession Exchange cmdlet issued',
    25739: 'Stop-UMPhoneSession Exchange cmdlet issued',
    25740: 'Test-DataClassification Exchange cmdlet issued',
    25741: 'Test-TextExtraction Exchange cmdlet issued',
}

EVENTS = {}
EVENTS.update(WINDOWS)
EVENTS.update(EXCHANGE)
EVENTS.update(SQL)
EVENTS.update(SECUTIRY)  # Use these descriptions over windows

if __name__ == '__main__':
    overlap = set(SECUTIRY) & set(WINDOWS)
    for evid in overlap:
        if SECUTIRY[evid] != WINDOWS[evid]:
            print(f'{evid}: {SECUTIRY[evid]} != {WINDOWS[evid]}')
