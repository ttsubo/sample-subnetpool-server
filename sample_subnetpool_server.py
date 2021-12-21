import uuid
import netaddr
import operator
import logging
import json
from bottle import Bottle, request, HTTPResponse, HTTPError

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(asctime)s:%(levelname)s:%(name)s:%(message)s',
                    level=logging.DEBUG)

app = Bottle()

DICT_DummySubnet = {}
DICT_DummySubnetPool = {}


def makeResponse(code, data, type):
    if type == "plain":
        r = HTTPResponse(status=code, body="{0}\n".format(data))
        r.set_header('Content-Type', 'text/plain')
    elif type == "json":
        body = json.dumps(data) + "\n"
        r = HTTPResponse(status=code, body=body)
        r.set_header('Content-Type', 'application/json')
    return r

def ip_version_from_int(ip_version_int):
    if ip_version_int == 4:
        return 'IPv4'
    if ip_version_int == 6:
        return 'IPv6'
    raise ValueError(_('Illegal IP version number'))


def is_attr_set(attribute):
    return not (attribute is None or
                attribute is ATTR_NOT_SPECIFIED)


def generate_uuid(dashed=True):
    if dashed:
        return str(uuid.uuid4())
    return uuid.uuid4().hex


class Sentinel(object):
    """A constant object that does not change even when copied."""
    def __deepcopy__(self, memo):
        # Always return the same object because this is essentially a constant.
        return self

    def __copy__(self):
        # called via copy.copy(x)
        return self


ATTR_NOT_SPECIFIED = Sentinel()

class NeutronException(Exception):
    """Base Neutron Exception.

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.
    """
    message = "An unknown exception occurred."

    def __init__(self, **kwargs):
        try:
            super(NeutronException, self).__init__(self.message % kwargs)
            self.msg = self.message % kwargs
        except Exception:
            with excutils.save_and_reraise_exception() as ctxt:
                if not self.use_fatal_exceptions():
                    ctxt.reraise = False
                    # at least get the core message out if something happened
                    super(NeutronException, self).__init__(self.message)

    def __str__(self):
        return self.msg

    def use_fatal_exceptions(self):
        """Is the instance using fatal exceptions.

        :returns: Always returns False.
        """
        return False


class NotFound(NeutronException):
    """A generic not found exception."""
    pass


class BadRequest(NeutronException):
    message = 'Bad %(resource)s request: %(msg)s.'


class SubnetPoolNotFound(NotFound):
    message = "Subnet pool %(subnetpool_id)s could not be found."


class MinPrefixSubnetAllocationError(BadRequest):
    message = "Unable to allocate subnet with prefix length %(prefixlen)s, " \
              "minimum allowed prefix is %(min_prefixlen)s."


class MaxPrefixSubnetAllocationError(BadRequest):
    message = "Unable to allocate subnet with prefix length %(prefixlen)s, " \
              "maximum allowed prefix is %(max_prefixlen)s."


class SubnetAllocationError(NeutronException):
    message = "Failed to allocate subnet: %(reason)s."

class PrefixVersionMismatch(BadRequest):
    message = "Cannot mix IPv4 and IPv6 prefixes in a subnet pool."


class DummySubnet(object):

    def __init__(self, project_id, id, name, network_id, ip_version, cidr, subnetpool_id):
        self._project_id = project_id
        self._id = id
        self._name = name
        self._network_id = network_id
        self._ip_version = ip_version
        self._cidr = cidr
        self._subnetpool_id = subnetpool_id

    @property
    def project_id(self):
        return self._project_id

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    @property
    def network_id(self):
        return self._network_id

    @property
    def ip_version(self):
        return self._ip_version

    @property
    def cidr(self):
        return self._cidr

    @property
    def subnetpool_id(self):
        return self._subnetpool_id

    def __repr__(self):
       return str({
            'project_id': self._project_id,
            'id': self._id,
            'name': self._name,
            'network_id': self._network_id,
            'ip_version': self._ip_version,
            'cidr': str(self._cidr),
            'subnetpool_id': self._subnetpool_id
        })

class DummySubnetPool(object):

    def __init__(self, project_id, name, ip_version, prefixes, default_prefixlen=None, max_prefixlen=None, min_prefixlen=None):
        self._project_id = project_id
        self._id = generate_uuid()
        self._name = name
        self._ip_version = ip_version
        self._prefixes = prefixes
        self._default_prefixlen = default_prefixlen
        self._max_prefixlen = max_prefixlen
        self._min_prefixlen = min_prefixlen

    def update_prefixes(self, prefixes):
        self._prefixes = prefixes
        return self

    @property
    def project_id(self):
        return self._project_id

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name


    @property
    def ip_version(self):
        return self._ip_version

    @property
    def prefixes(self):
        return self._prefixes

    @property
    def default_prefixlen(self):
        return self._default_prefixlen

    @property
    def max_prefixlen(self):
        return self._max_prefixlen

    @property
    def min_prefixlen(self):
        return self._min_prefixlen

    def __repr__(self):
        return str({
            'project_id': self._project_id,
            'id': self._id,
            'name': self._name,
            'ip_version': self._ip_version,
            'prefixes': [ str(prefix) for prefix in self._prefixes],
            'default_prefixlen': self._default_prefixlen,
            'max_prefixlen': self._max_prefixlen,
            'min_prefixlen': self._min_prefixlen
        })

class Pool(object):

    def __init__(self, subnetpool, context):
        self._subnetpool = subnetpool
        self._context = context

    def get_subnet_request_factory(self):
        return SubnetRequestFactory


class SubnetAllocator(Pool):

    def __init__(self, subnetpool, context):
        super(SubnetAllocator, self).__init__(subnetpool, context)

    def _get_allocated_cidrs(self):
        cidrs = []
        for subnet in DICT_DummySubnet.values():
            if subnet.subnetpool_id == self._subnetpool.id:
                cidrs.append(subnet.cidr)

        return cidrs

    def _get_available_prefix_list(self):
        prefixes = (x.cidr for x in self._subnetpool.prefixes)
        allocations = self._get_allocated_cidrs()
        prefix_set = netaddr.IPSet(iterable=prefixes)
        logging.debug("### prefix_set=[{0}]".format(prefix_set))
        allocation_set = netaddr.IPSet(iterable=allocations)
        logging.debug("### allocation_set=[{0}]".format(allocation_set))
        available_set = prefix_set.difference(allocation_set)
        logging.debug("### available_set=[{0}]".format(available_set))
        available_set.compact()
        return sorted(available_set.iter_cidrs(),
                      key=operator.attrgetter('prefixlen'),
                      reverse=True)

    def _allocate_any_subnet(self, request):
        prefix_pool = self._get_available_prefix_list()
        logging.debug("### prefix_pool=[{0}]".format(prefix_pool))
        for prefix in prefix_pool:
            if request.prefixlen >= prefix.prefixlen:
                subnet = next(prefix.subnet(request.prefixlen))
                gateway_ip = request.gateway_ip
                if not gateway_ip:
                    gateway_ip = subnet.network + 1

                return IpamSubnet(request.tenant_id,
                                  request.subnet_id,
                                  subnet.cidr,
                                  gateway_ip=gateway_ip)
        msg = "Insufficient prefix space to allocate subnet size /%s"
        raise SubnetAllocationError(reason=msg %
                                          str(request.prefixlen))

    def allocate_subnet(self, request):
        max_prefixlen = int(self._subnetpool.max_prefixlen)
        min_prefixlen = int(self._subnetpool.min_prefixlen)
        if request.prefixlen > max_prefixlen:
            raise MaxPrefixSubnetAllocationError(
                              prefixlen=request.prefixlen,
                              max_prefixlen=max_prefixlen)
        if request.prefixlen < min_prefixlen:
            raise MinPrefixSubnetAllocationError(
                              prefixlen=request.prefixlen,
                              min_prefixlen=min_prefixlen)

        return self._allocate_any_subnet(request)


class NeutronDbPool(SubnetAllocator):

    def allocate_subnet(self, subnet_request):
        if self._subnetpool:
            subnet = super(NeutronDbPool, self).allocate_subnet(subnet_request)
            subnet_request = subnet.get_details()

        # SubnetRequest must be an instance of SpecificSubnet
        if not isinstance(subnet_request, SpecificSubnetRequest):
            raise ipam_exc.InvalidSubnetRequestType(
                subnet_type=type(subnet_request))
        return NeutronDbSubnet.create_from_subnet_request(subnet_request,
                                                          self._context)


class SubnetRequestFactory(object):

    @classmethod
    def get_request(cls, context, subnet, subnetpool):
        subnet_id = subnet.get('id', generate_uuid())

        prefixlen = subnet['prefixlen']
        if not is_attr_set(prefixlen):
            prefixlen = int(subnetpool.default_prefixlen)

        return AnySubnetRequest(
            subnet['tenant_id'],
            subnet_id,
            ip_version_from_int(subnetpool.ip_version),
            prefixlen)


class SubnetRequest(object):

    def __init__(self, tenant_id, subnet_id,
                 gateway_ip=None, allocation_pools=None):
        self._tenant_id = tenant_id
        self._subnet_id = subnet_id
        self._gateway_ip = None
        self._allocation_pools = None

        if gateway_ip is not None:
            self._gateway_ip = netaddr.IPAddress(gateway_ip)

        if allocation_pools is not None:
            allocation_pools = sorted(allocation_pools)
            previous = None
            for pool in allocation_pools:
                if not isinstance(pool, netaddr.ip.IPRange):
                    raise TypeError(_("Ranges must be netaddr.IPRange"))
                if previous and pool.first <= previous.last:
                    raise ValueError(_("Ranges must not overlap"))
                previous = pool
            if 1 < len(allocation_pools):
                # Checks that all the ranges are in the same IP version.
                # IPRange sorts first by ip version so we can get by with just
                # checking the first and the last range having sorted them
                # above.
                first_version = allocation_pools[0].version
                last_version = allocation_pools[-1].version
                if first_version != last_version:
                    raise ValueError(_("Ranges must be in the same IP "
                                       "version"))
            self._allocation_pools = allocation_pools

        if self.gateway_ip and self.allocation_pools:
            if self.gateway_ip.version != self.allocation_pools[0].version:
                raise ValueError(_("Gateway IP version inconsistent with "
                                   "allocation pool version"))

    @property
    def tenant_id(self):
        return self._tenant_id

    @property
    def subnet_id(self):
        return self._subnet_id

    @property
    def gateway_ip(self):
        return self._gateway_ip

    @property
    def allocation_pools(self):
        return self._allocation_pools

    def _validate_with_subnet(self, subnet_cidr):
        if self.allocation_pools:
            if subnet_cidr.version != self.allocation_pools[0].version:
                raise ipam_exc.IpamValueInvalid(_(
                                "allocation_pools use the wrong ip version"))
            for pool in self.allocation_pools:
                if pool not in subnet_cidr:
                    raise ipam_exc.IpamValueInvalid(_(
                                "allocation_pools are not in the subnet"))


class AnySubnetRequest(SubnetRequest):
    WILDCARDS = {'IPv4': '0.0.0.0',
                 'IPv6': '::'}

    def __init__(self, tenant_id, subnet_id, version, prefixlen,
                 gateway_ip=None, allocation_pools=None):
        super(AnySubnetRequest, self).__init__(
            tenant_id=tenant_id,
            subnet_id=subnet_id,
            gateway_ip=gateway_ip,
            allocation_pools=allocation_pools)

        net = netaddr.IPNetwork(self.WILDCARDS[version] + '/' + str(prefixlen))
        self._validate_with_subnet(net)

        self._prefixlen = prefixlen

    @property
    def prefixlen(self):
        return self._prefixlen


class SpecificSubnetRequest(SubnetRequest):

    def __init__(self, tenant_id, subnet_id, subnet_cidr,
                 gateway_ip=None, allocation_pools=None):
        super(SpecificSubnetRequest, self).__init__(
            tenant_id=tenant_id,
            subnet_id=subnet_id,
            gateway_ip=gateway_ip,
            allocation_pools=allocation_pools)

        self._subnet_cidr = netaddr.IPNetwork(subnet_cidr)
        self._validate_with_subnet(self._subnet_cidr)

    @property
    def subnet_cidr(self):
        return self._subnet_cidr

    @property
    def prefixlen(self):
        return self._subnet_cidr.prefixlen


class IpamSubnet(object):

    def __init__(self,
                 tenant_id,
                 subnet_id,
                 cidr,
                 gateway_ip=None,
                 allocation_pools=None):
        self._req = SpecificSubnetRequest(
            tenant_id,
            subnet_id,
            cidr,
            gateway_ip=gateway_ip,
            allocation_pools=allocation_pools)

    def allocate(self, address_request):
        raise NotImplementedError()

    def deallocate(self, address):
        raise NotImplementedError()

    def get_details(self):
        return self._req


class NeutronDbSubnet(object):

    @classmethod
    def create_allocation_pools(cls, subnet_manager, context, pools, cidr):
        for pool in pools:
            # IPv6 addresses that start '::1', '::2', etc cause IP version
            # ambiguity when converted to integers by pool.first and pool.last.
            # Infer the IP version from the subnet cidr.
            ip_version = cidr.version
            subnet_manager.create_pool(
                context,
                netaddr.IPAddress(pool.first, ip_version).format(),
                netaddr.IPAddress(pool.last, ip_version).format())

    @classmethod
    def create_from_subnet_request(cls, subnet_request, ctx):
        ipam_subnet_id = generate_uuid()
        return cls(ipam_subnet_id,
                   ctx,
                   cidr=subnet_request.subnet_cidr,
                   gateway_ip=subnet_request.gateway_ip,
                   tenant_id=subnet_request.tenant_id,
                   subnet_id=subnet_request.subnet_id)

    def __init__(self, internal_id, ctx, cidr=None,
                 allocation_pools=None, gateway_ip=None, tenant_id=None,
                 subnet_id=None):
        self._cidr = cidr
        self._pools = allocation_pools
        self._gateway_ip = gateway_ip
        self._tenant_id = tenant_id
        self._subnet_id = subnet_id
        self._context = ctx

    def get_details(self):
        """Return subnet data as a SpecificSubnetRequest"""
        return SpecificSubnetRequest(
            self._tenant_id, self._subnet_id, self._cidr)


class DbBasePluginCommon(object):

    def _get_subnetpool(self, context, id):
        subnetpool = None
        for k, v in DICT_DummySubnetPool.items():
            if k == id:
                subnetpool = v
        if not subnetpool:
            raise SubnetPoolNotFound(subnetpool_id=id)
        return subnetpool

    def _make_subnet_args(self, detail, subnet, subnetpool_id):
        args = {'project_id': detail.tenant_id,
                'id': detail.subnet_id,
                'name': subnet['name'],
                'network_id': subnet['network_id'],
                'ip_version': subnet['ip_version'],
                'cidr': detail.subnet_cidr,
                'subnetpool_id': subnetpool_id}
        return args


class IpamBackendMixin(DbBasePluginCommon):

    def _save_subnet(self, context, network, subnet_args, subnet_request):
        subnet_id = subnet_args['id']
        subnet = DummySubnet(**subnet_args)
        DICT_DummySubnet[subnet_id] = subnet
        return subnet

    def _make_subnet_args(self, detail, subnet, subnetpool_id):
        args = super(IpamBackendMixin, self)._make_subnet_args(
            detail, subnet, subnetpool_id)
        return args


class IpamPluggableBackend(IpamBackendMixin):

    def allocate_subnet(self, context, network, subnet, subnetpool_id):
        subnetpool = None

        subnetpool = self._get_subnetpool(context, id=subnetpool_id)

        ipam_driver = NeutronDbPool(subnetpool, context)
        subnet_factory = ipam_driver.get_subnet_request_factory()
        subnet_request = subnet_factory.get_request(context, subnet,
                                                    subnetpool)
        ipam_subnet = ipam_driver.allocate_subnet(subnet_request)
        # get updated details with actually allocated subnet
        subnet_request = ipam_subnet.get_details()

        try:
            subnet = self._save_subnet(context,
                                       network,
                                       self._make_subnet_args(
                                           subnet_request,
                                           subnet,
                                           subnetpool_id),
                                       subnet_request)
        except Exception:
                logging.error("An exception occurred during subnet creation. "
                      "Reverting subnet allocation.")

        return subnet, ipam_subnet


@app.post('/subnetpools')
@app.post('/subnetpools/')
def create_subnetpool():
    MIN_PREFIX_IPV4_LEN = 8
    MAX_PREFIX_IPV4_LEN = 32
    MIN_PREFIX_IPV6_LEN = 64
    MAX_PREFIX_IPV6_LEN = 128

    logging.debug("### received post request={0}".format(request.json))
    request_info = request.json

    ip_version = None
    for prefix in request_info['subnetpool'].get("prefixes"):
        if not ip_version:
            ip_version = netaddr.IPNetwork(prefix).version
        elif netaddr.IPNetwork(prefix).version != ip_version:
            raise PrefixVersionMismatch()

    pool_args = {}
    pool_args["project_id"] = request_info['subnetpool'].get("project_id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    pool_args["name"] = request_info['subnetpool'].get("name")
    pool_args["prefixes"] = [netaddr.IPNetwork(prefix) for prefix in request_info['subnetpool'].get("prefixes")]
    pool_args["ip_version"] = ip_version
    if ip_version == 4:
        pool_args["default_prefixlen"] = request_info['subnetpool'].get("default_prefixlen", MIN_PREFIX_IPV4_LEN)
        pool_args["min_prefixlen"] = request_info['subnetpool'].get("min_prefixlen", MIN_PREFIX_IPV4_LEN)
        pool_args["max_prefixlen"] = request_info['subnetpool'].get("max_prefixlen", MAX_PREFIX_IPV4_LEN)
    elif ip_version == 6:
        pool_args["default_prefixlen"] = request_info['subnetpool'].get("default_prefixlen", MIN_PREFIX_IPV6_LEN)
        pool_args["min_prefixlen"] = request_info['subnetpool'].get("min_prefixlen", MIN_PREFIX_IPV6_LEN)
        pool_args["max_prefixlen"] = request_info['subnetpool'].get("max_prefixlen", MAX_PREFIX_IPV6_LEN)

    try:
        subnetpool = DummySubnetPool(**pool_args)
        DICT_DummySubnetPool[subnetpool.id] = subnetpool
        logging.debug("Creating subnetpool -> [{0}]".format(repr(subnetpool)))
        subnetpool_info = {
            'project_id': subnetpool.project_id,
            'id': subnetpool.id,
            'name': subnetpool.name,
            'ip_version': subnetpool.ip_version,
            'prefixes': [ str(prefix) for prefix in subnetpool.prefixes],
            'default_prefixlen': subnetpool.default_prefixlen,
            'max_prefixlen': subnetpool.max_prefixlen,
            'min_prefixlen': subnetpool.min_prefixlen
        }
        response_body = {'subnetpool': subnetpool_info}
    except NeutronException as e:
        logging.error("ErrorMessage=[{0}]".format(e))
        return HTTPError(status=500, body=e)
    return makeResponse(200, response_body, "json")


@app.get('/subnetpools')
@app.get('/subnetpools/')
def get_subnetpools():
    subnetpool_list = []
    for subnetpool in DICT_DummySubnetPool.values():
        subnetpool_info = {
            'project_id': subnetpool.project_id,
            'id': subnetpool.id,
            'name': subnetpool.name,
            'ip_version': subnetpool.ip_version,
            'prefixes': [ str(prefix) for prefix in subnetpool.prefixes],
            'default_prefixlen': subnetpool.default_prefixlen,
            'max_prefixlen': subnetpool.max_prefixlen,
            'min_prefixlen': subnetpool.min_prefixlen
        }
        subnetpool_list.append(subnetpool_info)
    response_body = {'subnetpools': subnetpool_list}
    return makeResponse(200, response_body, "json")


@app.get('/subnetpools/<subnetpool_id>')
@app.get('/subnetpools/<subnetpool_id>/')
def get_subnetpool(subnetpool_id):
    subnetpool = DICT_DummySubnetPool[subnetpool_id]
    subnetpool_info = {
        'project_id': subnetpool.project_id,
        'id': subnetpool.id,
        'name': subnetpool.name,
        'ip_version': subnetpool.ip_version,
        'prefixes': [ str(prefix) for prefix in subnetpool.prefixes],
        'default_prefixlen': subnetpool.default_prefixlen,
        'max_prefixlen': subnetpool.max_prefixlen,
        'min_prefixlen': subnetpool.min_prefixlen
    }
    response_body = {'subnetpool': subnetpool_info}
    return makeResponse(200, response_body, "json")


@app.put('/subnetpools/<subnetpool_id>')
@app.put('/subnetpools/<subnetpool_id>/')
def update_subnetpool(subnetpool_id):
    logging.debug("### received update subnetpool -> id=[{0}]".format(subnetpool_id))
    request_info = request.json

    pool_args = {}
    pool_args["prefixes"] = [netaddr.IPNetwork(prefix) for prefix in request_info['subnetpool'].get("prefixes")]
    subnetpool = DICT_DummySubnetPool[subnetpool_id].update_prefixes(**pool_args)
    subnetpool_info = {
        'project_id': subnetpool.project_id,
        'id': subnetpool.id,
        'name': subnetpool.name,
        'ip_version': subnetpool.ip_version,
        'prefixes': [ str(prefix) for prefix in subnetpool.prefixes],
        'default_prefixlen': subnetpool.default_prefixlen,
        'max_prefixlen': subnetpool.max_prefixlen,
        'min_prefixlen': subnetpool.min_prefixlen
    }
    response_body = {'subnetpool': subnetpool_info}
    return makeResponse(200, response_body, "json")


@app.delete('/subnetpools/<subnetpool_id>')
@app.delete('/subnetpools/<subnetpool_id>/')
def delete_subnetpool(subnetpool_id):
    logging.debug("### received delete subnetpool -> id=[{0}]".format(subnetpool_id))
    deleted_subnetpool = DICT_DummySubnetPool.pop(subnetpool_id)
    logging.debug("Deleting subnetpool -> [{0}]".format(repr(deleted_subnetpool)))
    subnetpool_info = {
        'project_id': deleted_subnetpool.project_id,
        'id': deleted_subnetpool.id,
        'name': deleted_subnetpool.name,
        'ip_version': deleted_subnetpool.ip_version,
        'prefixes': [ str(prefix) for prefix in deleted_subnetpool.prefixes],
        'default_prefixlen': deleted_subnetpool.default_prefixlen,
        'max_prefixlen': deleted_subnetpool.max_prefixlen,
        'min_prefixlen': deleted_subnetpool.min_prefixlen
    }
    response_body = {'subnetpool': subnetpool_info}
    return makeResponse(200, response_body, "json")


@app.post('/subnets')
@app.post('/subnets/')
def create_subnet():
    logging.debug("### received post request={0}".format(request.json))
    request_info = request.json

    subnet_args = {}
    subnet_args["tenant_id"] = request_info['subnet'].get("tenant_id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    subnet_args["ip_version"] = request_info['subnet'].get("ip_version")
    subnet_args["name"] = request_info['subnet'].get("name")
    subnet_args["network_id"] = request_info['subnet'].get("network_id")
    subnetpool_id = request_info['subnet'].get("subnetpool_id")
    subnet_args["subnetpool_id"] = subnetpool_id
    subnet_args["prefixlen"] = request_info['subnet'].get("prefixlen", ATTR_NOT_SPECIFIED)

    ipam = IpamPluggableBackend()
    try:
        subnet, ipam_subnet = ipam.allocate_subnet(None, None, subnet_args, subnetpool_id=subnetpool_id)
        logging.debug("Creating subnet -> [{0}]".format(repr(subnet)))
        subnet_info = {
            'project_id': subnet.project_id,
            'id': subnet.id,
            'name': subnet.name,
            'network_id': subnet.network_id,
            'ip_version': subnet.ip_version,
            'cidr': str(subnet.cidr),
            'subnetpool_id': subnet.subnetpool_id
        }
        response_body = {'subnet': subnet_info}
    except NeutronException as e:
        logging.error("ErrorMessage=[{0}]".format(e))
        return HTTPError(status=500, body=e)
    return makeResponse(200, response_body, "json")


@app.get('/subnets')
@app.get('/subnets/')
def get_subnets():
    subnet_list = []
    for subnet in DICT_DummySubnet.values():
        subnet_info = {
            'project_id': subnet.project_id,
            'id': subnet.id,
            'name': subnet.name,
            'network_id': subnet.network_id,
            'ip_version': subnet.ip_version,
            'cidr': str(subnet.cidr),
            'subnetpool_id': subnet.subnetpool_id
        }
        subnet_list.append(subnet_info)
    response_body = {'subnets': subnet_list}
    return makeResponse(200, response_body, "json")


@app.get('/subnets/<subnet_id>')
@app.get('/subnets/<subnet_id>/')
def get_subnet(subnet_id):
    subnet = DICT_DummySubnet[subnet_id]
    subnet_info = {
        'project_id': subnet.project_id,
        'id': subnet.id,
        'name': subnet.name,
        'network_id': subnet.network_id,
        'ip_version': subnet.ip_version,
        'cidr': str(subnet.cidr),
        'subnetpool_id': subnet.subnetpool_id
    }
    response_body = {'subnet': subnet_info}
    return makeResponse(200, response_body, "json")


@app.delete('/subnets/<subnet_id>')
@app.delete('/subnets/<subnet_id>/')
def delete_subnet(subnet_id):
    logging.debug("### received delete subnet -> id=[{0}]".format(subnet_id))
    deleted_subnet = DICT_DummySubnet.pop(subnet_id)
    logging.debug("Deleting subnet -> [{0}]".format(repr(deleted_subnet)))
    subnet_info = {
        'project_id': deleted_subnet.project_id,
        'id': deleted_subnet.id,
        'name': deleted_subnet.name,
        'network_id': deleted_subnet.network_id,
        'ip_version': deleted_subnet.ip_version,
        'cidr': str(deleted_subnet.cidr),
        'subnetpool_id': deleted_subnet.subnetpool_id
    }
    response_body = {'subnet': subnet_info}
    return makeResponse(200, response_body, "json")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=True)
