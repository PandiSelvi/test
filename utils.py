import StringIO
import os
import subprocess
import time
import sys
import commands
import httplib
import httplib2
import sys
import json
import time
import os
import random
import signal
import subprocess
import sys
from httplib import IncompleteRead
import datetime
import paramiko
import shlex


def _do_request(tenant_id, auth_token, method, body='', service="", path=""):
    """ Common method for all API calls
       Return value : content-Content of API Response """

    if service == "volumes":
        url = '%s%s/%s' % ("http://10.0.2.15:8776/v2/", tenant_id, path)
    elif service == "glance":
        url = '%s%s' % ("http://10.0.2.15:9292/v1/", path)
    elif service == "servers":
        url = '%s%s/%s' % ("http://10.0.2.15:8774/v2/", tenant_id, path)
    elif service == "network":
        url = '%s%s' % ("http://10.0.2.15:9696/v2.0/", path)
    else:
        raise Exception("unknown service")

    conn = httplib2.Http(disable_ssl_certificate_validation=True)

    resp, content = conn.request(url, method, body,
                                 headers={"Content-Type": "application/json",
                                          "X-Auth-Token": auth_token})
    if int(resp['status']) in [200, 201, 202, 203, 204]:
        if content:
            content = json.loads(content)
        return content
    else:
        raise Exception('%s %s failed' % (method, url), body, resp, content)


def keystone_login(tenant, username, password):
    """ Kesytone login
        Return values: tenant_id,auth_token """

    conn = httplib2.Http(disable_ssl_certificate_validation=True)
    url = '%s/v2.0/tokens' % ("http://127.0.0.1:5000")
    body = json.dumps({'auth':
                       {'tenantName': tenant,
                        'passwordCredentials': {'username': username,
                                                'password': password}}})
    resp, content = conn.request(url, 'POST', body,
                                 headers={"Content-Type": "application/json", "Content-Type": "application/json", "User-Agent": "python-cinderclient"})
    if resp['status'] == '200' and content:
        content = json.loads(content)
        return (content['access']['token']['tenant']['id'],
                content['access']['token']['id'])
    else:
        raise Exception('Keystone login POST %s failed' %
                        url, body, resp, content)


def volume_create(tenant_id, auth_token, name, size, image_id=''):
    """ Creates bootable or non bootable volume w.r.t image_id parameter
        Return value: content-Content of API response """

    if image_id:
        content = _do_request(tenant_id, auth_token, method="POST", body='{"volume":{"name": "%s", "size": "%s", "image_id": "%s"}}' % (
            name, size, image_id), service="volumes", path="volumes")
        return content
    else:
        content = _do_request(tenant_id, auth_token, method="POST", body='{"volume":{"name": "%s", "size": "%s"}}' % (
            name, size), service="volumes", path="volumes")
    return content


def volume_create_while_creating_instance(
        tenant_id, auth_token, image_id, size, key_name, instance_name, flavor, network, security_group, delete="false"):
    """ Creates bootable volume while creating instance
       Return value: content-Content of API response """
    net_id = network_id(tenant_id, auth_token, network)
    content = _do_request(tenant_id, auth_token, method="POST", body='{"server": {"name": "%s", "imageRef": "", "block_device_mapping_v2": [{"boot_index": "0", "uuid": "%s", "volume_size": "%s", "source_type": "image", "destination_type": "volume", "delete_on_termination": %s}],"key_name": "%s", "flavorRef": "%s", "max_count": 1, "min_count": 1,"networks": [{"uuid": "%s"}],"security_groups": [{"name": "%s"}]}}' % (
        instance_name, image_id, size, delete, key_name, flavor, net_id, security_group), service="servers", path="os-volumes_boot")
    return content


def volume_boot_attach_while_creating_instance(
        tenant_id, auth_token, volume_id, key_name, instance_name, flavor, network, security_group, delete="false"):
    """ Creates instance with bootable volume
       Return value: content-Content of API response """

    net_id = network_id(tenant_id, auth_token, network)
    content = _do_request(tenant_id, auth_token, method="POST", body='{"server": {"name": "%s", "imageRef": "", "block_device_mapping_v2": [{"source_type": "volume", "delete_on_termination": %s, "boot_index": 0, "uuid": "%s", "destination_type": "volume"}],"key_name": "%s", "flavorRef": "%s", "max_count": 1, "min_count": 1, "networks": [{"uuid": "%s"}],"security_groups": [{"name": "%s"}]}}' % (
        instance_name, delete, volume_id, key_name, flavor, net_id, security_group), service="servers", path="os-volumes_boot")
    return content


def volume_attach_while_creating_instance(
        tenant_id, auth_token, image_id, volume_id, key_name, instance_name, flavor, network, security_group, delete="false"):
    """ Creates instance with non bootable volume attached
       Return value: content-Content of API response """

    net_id = network_id(tenant_id, auth_token, network)
    content = _do_request(tenant_id, auth_token, method="POST", body='{"server": {"name": "%s", "imageRef": "%s", "block_device_mapping_v2": [{"boot_index": "0", "uuid": "%s", "source_type": "volume", "destination_type": "volume", "delete_on_termination": %s}],"key_name": "%s", "flavorRef": "%s", "max_count": 1, "min_count": 1,"networks": [{"uuid": "%s"}],"security_groups": [{"name": "%s"}]}}' % (
        instance_name, image_id, volume_id, delete, key_name, flavor, net_id, security_group), service="servers", path="os-volumes_boot")
    return content


def is_volume_available(tenant_id, auth_token, volume_id):
    """ Checks if a volume is in available state
       Return volume: True if available,volume_status if not available """

    content = volume_details(tenant_id, auth_token, volume_id)
    while content["volume"]["status"] == "creating" or content["volume"][
            "status"] == "downloading" or content["volume"]["status"] == "restoring-backup":
        time.sleep(5)
        content = volume_details(tenant_id, auth_token, volume_id)
        content["volume"]["status"]
    if content["volume"]["status"] == "available":
        return True
    else:
        return content["volume"]["status"]


def volume_details(tenant_id, auth_token, volume_id):
    """ Returns details of a volume
        Return value: content-Content of API response """
    content = _do_request(tenant_id, auth_token, method="GET",
                          body='', service="volumes", path="volumes/%s" % (volume_id))
    return content


def volume_list(tenant_id, auth_token):
    """ Returns list of volumes
       Return value: content-Content of API response """
    content = _do_request(tenant_id, auth_token, method="GET",
                          body='', service="volumes", path="volumes")
    return content


def volume_attach(tenant_id, auth_token, server_id, volume_id, device=''):
    """Attaches volume to an instance
      Return value: content-Content of API response"""
    content = _do_request(tenant_id, auth_token, method="POST", body='{"volumeAttachment": {"device":"%s", "volumeId": "%s"}}' % (
        device, volume_id), service="servers", path="servers/%s/os-volume_attachments" % server_id)
    return content


def volume_detach(tenant_id, auth_token, server_id, volume_id):
    """Detaches volume to an instance
      Return value: content-Content of API response"""

    content = _do_request(tenant_id, auth_token, method="DELETE", body='', service="servers",
                          path="servers/%s/os-volume_attachments/%s" % (server_id, volume_id))
    return content


def volume_delete(tenant_id, auth_token, volume_id):
    """ Deletes a volume
        Return value: True-if not deleted,False-if deleted"""
    content = _do_request(tenant_id, auth_token, method="DELETE",
                          body='', service="volumes", path="volumes/%s" % (volume_id))

    try:
        details = volume_details(tenant_id, auth_token, volume_id)
        if details["volume"]["status"] == "in-use" or "available":
            time.sleep(15)
        while details["volume"]["status"] == "deleting":
            time.sleep(5)
            details = volume_details(tenant_id, auth_token, volume_id)

    except Exception as e:
        if "Volume could not be found" in str(e):
            return False
    volumes = volume_list(self.tenant_id, self.auth_token)
    for volume in range(len(volumes["volumes"])):
        if content["volumes"][volume]["id"] == volume_id:
            return True


def create_filesystem(instance_ip, device, mount_dir):
    """ Creates filesystem on a volume attached to an instance
        Return value: "Filesystem Created" """
    ssh = paramiko.SSHClient()
    key_file = open('/home/ubuntu/devstack/oskey1.priv', 'r')
    string = key_file.read()
    keyfile = StringIO.StringIO(string)
    mykey = paramiko.RSAKey.from_private_key(keyfile)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username='cirros', pkey=mykey)
    stdin, stdout, stderr = ssh.exec_command(
        "sudo /usr/sbin/mkfs.ext3 -b 1024 %s" % device, get_pty=True)
    output = stdout.readlines()
    stdin, stdout, stderr = ssh.exec_command("sudo /sbin/blkid /dev/vd*")
    output = stdout.readlines()
    ssh.close()
    for line in output:
        if device in line:
            return "Filesystem Created"


def mount_volume(instance_ip, device, mount_dir):
    """Mounts volume with the given directory
       Return value : "Successfully mounted" """
    ssh = paramiko.SSHClient()
    key_file = open('/home/ubuntu/devstack/oskey1.priv', 'r')
    string = key_file.read()
    keyfile = StringIO.StringIO(string)
    mykey = paramiko.RSAKey.from_private_key(keyfile)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username='cirros', pkey=mykey)
    stdin, stdout, stderr = ssh.exec_command("sudo mkdir %s" % mount_dir)
    stdin, stdout, stderr = ssh.exec_command(
        "sudo mount %s %s" % (device, mount_dir))
    time.sleep(60)
    stdin, stdout, stderr = ssh.exec_command("sudo /sbin/blkid /dev/vd*")
    output = stdout.readlines()
    stdin, stdout, stderr = ssh.exec_command("sudo df -h")
    output = stdout.readlines()
    ssh.close()
    for i in output:
        if device and mount_dir in i:
            return "Successfully mounted"


def unmount_volume(instance_ip, mount_dir):
    """ Unmounts a volume
        Return value: "Successfully unmounted" """
    ssh = paramiko.SSHClient()
    key_file = open('/home/ubuntu/devstack/oskey1.priv', 'r')
    string = key_file.read()
    keyfile = StringIO.StringIO(string)
    mykey = paramiko.RSAKey.from_private_key(keyfile)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username='cirros', pkey=mykey)
    stdin, stdout, stderr = ssh.exec_command("sudo umount %s " % (mount_dir))
    stdin, stdout, stderr = ssh.exec_command("sudo df -h")
    output = stdout.readlines()
    ssh.close()
    for i in output:
        if mount_dir not in i:
            return "Successfully unmounted"


def write_data_on_volume(instance_ip, block_size, count, mount_dir):
    """ Writes data on volume with given size
        Return value : None """
    ssh = paramiko.SSHClient()
    key_file = open('/home/ubuntu/devstack/oskey1.priv', 'r')
    string = key_file.read()
    keyfile = StringIO.StringIO(string)
    mykey = paramiko.RSAKey.from_private_key(keyfile)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username='cirros', pkey=mykey)
    if mount_dir == "/":
        stdin, stdout, stderr = ssh.exec_command(
            "sudo dd if=/dev/zero of=%stest.img bs=%d count=%d" % (mount_dir, block_size, count))
    else:
        stdin, stdout, stderr = ssh.exec_command(
            "sudo dd if=/dev/zero of=%s/test.img bs=%d count=%d" % (mount_dir, block_size, count))
        stdout.readlines()
        ssh.close()


def is_file_exists(instance_ip, mount_dir, file_size, file_name="test.img"):
    """ Checks if a file with a given size exists in a directory
       Return value: True """
    ssh = paramiko.SSHClient()
    key_file = open('/home/ubuntu/devstack/oskey1.priv', 'r')
    string = key_file.read()
    keyfile = StringIO.StringIO(string)
    mykey = paramiko.RSAKey.from_private_key(keyfile)
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(instance_ip, username='cirros', pkey=mykey)
    stdin, stdout, stderr = ssh.exec_command("cd %s;""ls -l;" % mount_dir)
    time.sleep(30)
    output = stdout.readlines()
    ssh.close()
    for line in output:
        if file_name in line:
            details = shlex.split(line)
            if int(details[4]) == file_size:
                return True
    raise Exception("File %s not found" % file_name)


def backup_create(tenant_id, auth_token, volume_id, name):
    """ Creates a backup for volume
        Return value: content-Content of API response """
    content = _do_request(tenant_id, auth_token, method="POST", body='{"backup": {"description": null, "container": null, "name": "%s", "volume_id": "%s"}}' % (
        name, volume_id), service="volumes", path="backups")
    return content


def is_backup_available(tenant_id, auth_token, backup_id):
    """ Checks if a backup is in available state
        Return value : True if available ,False if not available """
    content = backup_details(tenant_id, auth_token, backup_id)
    while content["backup"]["status"] == "creating":
        time.sleep(5)
        content = backup_details(tenant_id, auth_token, backup_id)
    if content["backup"]["status"] == "available":
        return True
    else:
        return False


def backup_restore(tenant_id, auth_token, backup_id, volume_id="null"):
    """ Restores a backup
     Return value: content-Content of API Response"""
    content = _do_request(tenant_id, auth_token, method="POST", body='{"restore":{"volume_id": %s}}' % (
        volume_id), service="volumes", path="backups/%s/restore" % (backup_id))
    return content


def backup_list(tenant_id, auth_token):
    """Lists all backups
       Return value: content-Content of API Response"""
    content = _do_request(tenant_id, auth_token, method="GET",
                          body='', service="volumes", path="backups")
    return content


def backup_delete(tenant_id, auth_token, backup_id):
    """Deletes a backup
       Return value: True if backup still exists, False if deleted """
    content = _do_request(tenant_id, auth_token, method="DELETE",
                          body='', service="volumes", path="backups/%s" % (backup_id))
    try:
        details = backup_details(tenant_id, auth_token, backup_id)
        while details["backup"]["status"] == "deleting":
            time.sleep(5)
            details = backup_details(tenant_id, auth_token, backup_id)
    except Exception as e:
        if "Backup %s could not be found" % backup_id in str(e):
            return False
    backups = backup_list(tenant_id, auth_token)
    for backup in range(len(backups)):
        if backups["backups"][backup]["id"] == backup_id:
            return True


def backup_details(tenant_id, auth_token, backup_id):
    """ Gets details of a  backup
       Return value: content-Content of API Response """
    content = _do_request(tenant_id, auth_token, method='GET',
                          body='', service="volumes", path='backups/%s' % backup_id)
    return content

# Instance


def instance_create(tenant_id, auth_token, server_name, image_ref, flavor, key_name, network, security_group):
    """ Creates an instance
        Return value : instance_id """
    net_id = network_id(tenant_id, auth_token, network)
    body = ('{"server": {"name": "%s", "imageRef": "%s", "key_name": "%s", "flavorRef": "%d", "max_count": 1, "min_count": 1, "networks": [{"uuid": "%s"}],"security_groups": [{"name": "%s"}]}}'
            % (server_name, image_ref, key_name, flavor, net_id, security_group))
    content = _do_request(tenant_id, auth_token, method="POST",
                          body=body, service="servers", path="servers")
    return content['server']['id']


def instance_create_2(tenant_id, auth_token, volume_id, server_name, flavor, delete=False):
    """ """
    content = _do_request(tenant_id, auth_token, method="POST", body='{"server": {"name": "%s", "imageRef": "", "block_device_mapping_v2": [{"source_type": "volume", "delete_on_termination": %s, "boot_index": 0, "uuid": "%s", "destination_type": "volume"}], "flavorRef": "%s", "max_count": 1, "min_count": 1}}' % (
        server_name, delete, volume_id, flavor), service="servers", path="os-volumes_boot")
    return content


def is_instance_active(tenant_id, auth_token, instance_id):
    """Checks if an instance is active
       Return value : True if active,False if not active"""
    content = _do_request(tenant_id, auth_token, method='GET',
                          body='', service="servers", path='servers/%s' % instance_id)
    status = content['server']['status']
    while content['server']['status'] == 'BUILD':
        time.sleep(5)
        content = _do_request(tenant_id, auth_token, method='GET',
                              body='', service="servers", path='servers/%s' % instance_id)
    if content['server']['status'] == 'ACTIVE':
        return True
    elif content['server']['status'] == 'ERROR':
        details = instance_details(tenant_id, auth_token, instance_id)
        raise Exception('Instance went into ERROR state',
                        details['server']['fault'])
    else:
        return False


def instance_list(tenant_id, auth_token):
    """Lists all instances
       Return value: content-Content of API Response"""
    content = _do_request(tenant_id, auth_token, method="GET",
                          body='', service="servers", path="servers")
    return content


def instance_delete(tenant_id, auth_token, instance_id):
    """ Deletes an instance
        Return value: True if instance found in instance list, False if instance found in instance list"""
    content = _do_request(tenant_id, auth_token, method="DELETE",
                          body='', service="servers", path="servers/%s" % (instance_id))

    try:
        details = instance_details(tenant_id, auth_token, instance_id)
        if details["server"]["status"] == "ACTIVE" or "SHUTOFF":
            time.sleep(60)
            details = instance_details(tenant_id, auth_token, instance_id)
        while details["server"]["status"] == "deleting":
            time.sleep(5)
            details = instance_details(tenant_id, auth_token, instance_id)
    except Exception as e:
        if "Instance %s could not be found" % instance_id in str(e):
            return False
    instances = instance_list(tenant_id, auth_token)
    for instance in range(len(instances)):
        if instances["servers"][instance]["id"] == instance_id:
            return True


def instance_ip_address(tenant_id, auth_token, instance_id):
    """ Finds instance ip address with instance name
        Return value : ip_address """
    content = _do_request(tenant_id, auth_token, method='GET',
                          body='', service="servers", path='servers/%s' % instance_id)
    ip_address = content['server']['addresses']['private'][1]['addr']
    return ip_address


def instance_details(tenant_id, auth_token, instance_id):
    """ Gets details of an instance
       Return value: content-Content of API Response"""
    content = _do_request(tenant_id, auth_token, method='GET',
                          body='', service="servers", path='servers/%s' % instance_id)
    return content


def instance_id(tenant_id, auth_token, instance_name):
    """ Finds instance_id address with instance name
        Return value : instance_id """
    content = _do_request(tenant_id, auth_token, method='GET',
                          body='', service="servers", path='servers')
    for instance in content['servers']:
        if instance['name'] == instance_name:
            return instance['id']
    raise Exception('Cannot find server')


def nova_stop_instance(tenant_id, auth_token, instance_name):
    """ Stops an instance
        Return value : content-Content of API Response """
    content = _do_request(tenant_id, auth_token, method='POST',
                          body='{"os-stop": null}', service="servers", path='servers/%s/action' % instance_name)
    return content


def nova_start_instance(tenant_id, auth_token, instance_name):
    """ Starts an instance
        Return value : content-Content of API Response """
    content = _do_request(tenant_id, auth_token, method='POST',
                          body='{"os-start": null}', service="servers", path='servers/%s/action' % instance_name)
    return content


def image_id(tenant_id, auth_token, image_name):
    """ Finds image_id address with instance name
        Return value : image_id """
    content = _do_request(tenant_id, auth_token, method="GET",
                          body='', service="glance", path="images")
    for image in content['images']:
        if image['name'] == image_name:
            return image['id']
    raise Exception('Cannot find image')


def instance_mac_id_fixed(tenant_id, auth_token, instance_id):
    """ Finds the mac_id for an instance
       Return value : mac_id """
    content = instance_details(tenant_id, auth_token, instance_id)
    for ip in range(len(content["server"]["addresses"]["private"])):
        if content["server"]["addresses"]["private"][ip]["OS-EXT-IPS:type"] == "fixed":
            mac_id = content["server"]["addresses"][
                "private"][ip]["OS-EXT-IPS-MAC:mac_addr"]
            return mac_id


def instance_port_id(tenant_id, auth_token, instance_id):
    """ Finds the port_id for an instance
        Return value : port_id """
    content = _do_request(tenant_id, auth_token, method='GET', body='',
                          service="network", path='ports.json?device_id=%s' % instance_id)
    instance_mac_id = instance_mac_id_fixed(tenant_id, auth_token, instance_id)
    for port in range(len(content["ports"])):
        if content["ports"][port]["mac_address"] == instance_mac_id:
            port_id = content["ports"][port]["id"]
            return port_id


def floating_ip_associate(tenant_id, auth_token, network, instance_id):
    """ Associates floating ip to an instance
        Return value : floating_ip """
    port_id = instance_port_id(tenant_id, auth_token, instance_id)
    floating_ip_id = floating_ip_create(tenant_id, auth_token, network)
    content = _do_request(tenant_id, auth_token, method='PUT', body='{"floatingip": {"port_id": "%s"}}' %
                          port_id, service="network", path='floatingips/%s.json' % floating_ip_id)
    if content["floatingip"]["port_id"] == port_id:
        floating_ip = content["floatingip"]["floating_ip_address"]
        return floating_ip


def network_id(tenant_id, auth_token, network_name):
    """ Finds the network_id for a network
       Return value : network_id """
    content = _do_request(tenant_id, auth_token, method='GET',
                          body='', service="network", path='networks.json')
    for network in range(len(content["networks"])):
        if content["networks"][network]["name"] == network_name:
            network_id = content["networks"][network]["id"]
            return network_id


def floating_ip_create(tenant_id, auth_token, network):
    """ Creates a floating ip
        Return value : floatingip_id """
    net_id = network_id(tenant_id, auth_token, network)
    content = _do_request(tenant_id, auth_token, method='POST',
                          body='{"floatingip": {"floating_network_id": "%s"}}' % net_id, service="network", path='floatingips.json')
    floatingip_id = content['floatingip']["id"]
    return floatingip_id


def floating_ip_delete(tenant_id, auth_token, floating_ip_id):
    """ Deletes a floating ip
        Return value: True is not deleted,False if deleted """
    content = _do_request(tenant_id, auth_token, method='DELETE', body='',
                          service="network", path="floatingips/%s" % floating_ip_id)
    ip_list = floating_ip_list(tenant_id, auth_token)
    for ip in range(len(ip_list["floatingips"])):
        if ip_list["floatingips"][ip]["id"] == floating_ip_id:
            return True
        else:
            return False


def floating_ip_list(tenant_id, auth_token):
    """ Lists all floating ips
        Return value : content-Content of API response"""
    content = _do_request(tenant_id, auth_token, method='GET',
                          body='', service="network", path="floatingips.json")
    return content

######## Other resuable methods########


def random_pick(a_list):
    """ Picks a random value in a list does not return the previous value
         Return value : value """
    previous_value = None
    while True:
        value = random.choice(a_list)
        if value != previous_value:
            yield value
            previous_value = value
