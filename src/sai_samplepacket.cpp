// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco").
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// END_LEGAL

#include "sai_samplepacket.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_svi_port.h"
#include "sai_device.h"
#include "sai_logger.h"
#include <arpa/inet.h>

//          ------------ SAI Packet Sampling... A very brief story -------------
//
// SAI currently allows packet sampling in two modes -- Slow path mode, and mirror sampling mode.
// 1. Slow path mode is used for sampling packets on ports (in ingress or egress direction) and
//    sent to cpu port.
// 2. Mirror sampling mode. In this mode, sampled packets on port (packets in ingress or
//    egress direction) are sent to destination as per mirror object. In this mode,
//    two objects are used. Packet sampling object that specifies rate of sampling and
//    mirror session object that specifies sampled packet destination and sampled
//    packet encapsulation.
// How do we make it work on Silicon one ?
//
// 1. For slow path sampling mode, when a packet sample object is created, an exclusive
//    mirror command for this purpose is created and used for sampling packets
//    on any attached port and sent to cpu. If a second packet sample object is
//    created with slow path mode, a second device mirror command is created
//    and that command is used to create a copy send to cpu where ever the second
//    packet sample object is attached to. (Same packet sample object can be attached
//    to more than one ethernet port)
//
// 2. Mirror sampling mode is a bit convoluted. In order to sample packets in this mode,
//    two sai objects are used. A packet sample object that is meant to be used to control
//    sampling rate and a set of mirror session objects that decides sampled packet
//    format or encaps and destination.
//    Modus Operandi for packet sampling using mirror objects
//      1. NOS creates mirror session objects with attributes specified for encap and destination.
//      2. NOS creates packet sampling object. Only one per direction and per ethernet port
//         is allowed.
//      3. NOS can attach mirror session object/s as packet sampler objects to use on a port.
//      4. NOS can attach packet sampling object that specifies sample rate on a port.
//      5. Order of [3] and [4] is not specified. Hence the implementation allows
//         attachment to a port either order; [3] and then [4] or [4] and then [3]
//      6. Mirror session objects can be shared by two or more packet sampler objects
//         with their own sampling rate.
//      7. Since shared set of mirror session objects across more than one packet sampler,
//         are sampled at different rates as per packet sample object attached to port,
//         whenever a sample mirror session is used on a port by packet sample object,
//         a device mirror command instance is created that is local to the port's usage.
//         The sampling rate applied/programmed is matched with sampling rate specified
//         in packet sample object.
//      8. [7] essentially means using an example
//         Sample mirror set = { Mirror Session 1, Mirror Session 2 }
//         Packet Sample object set = { PacketSampler1, PacketSampler2 }
//         Port Set = {Ethernet Port1, Ethernet Port2}
//         For the above example case...
//         If {Sampler1 and MirrorSession1} is attached to Port1, then
//             - A new device mirror command is created. Sampling rate is set to match
//               sampling-rate in Sampler1.
//             - The new device mirror command is programmed on all logical ports
//               present on the ethernet port.
//             - When sampling rate in Sampler1 is changed, then sampling rate on the
//               newly created device command is updated. Hence all logical ports will
//               now sample at new rate.
//
//         If same {Sampler1, MirrorSession1} is attached on port2, instead of
//         sharing already created device mirror command (done when they were attached
//         to Port1) for simiplity reasons, a new device mirror command for port2 is
//         created. This device mirror command is used on port2 alone.
//      9. [8] sacrifies mirror command resources for the sake simpler implementation.
//         For now, there is no concern with this approach. NOS have promised to use
//         very few instances of packet sampling objects and on very few ports.
//         The cross product if it exceeds 16, device resources for mirroring/sampling
//         will be stressed.
//

namespace silicon_one
{
namespace sai
{
using namespace std;

static constexpr int MAX_SAMPLEPACKET_SESSIONS = 32;
// default constructor for use by automatic serialization tool
sai_samplepacket::sai_samplepacket() : m_samplepacket_db(SAI_OBJECT_TYPE_SAMPLEPACKET, MAX_SAMPLEPACKET_SESSIONS, 0, 1)
{
}

sai_samplepacket::sai_samplepacket(std::shared_ptr<lsai_device> sai_dev)
    : m_sdev(sai_dev), m_samplepacket_db(SAI_OBJECT_TYPE_SAMPLEPACKET, MAX_SAMPLEPACKET_SESSIONS, 0, 1)
{
}

sai_samplepacket::~sai_samplepacket() = default;

// clang-format off
extern const sai_attribute_entry_t samplepacket_attribs[] = {
    // id, mandatory_on_create, valid_for_create, valid_for_set, valid_for_get, name
    {SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE, true, true, true, true, "sample rate", SAI_ATTR_VAL_TYPE_U32},
    {SAI_SAMPLEPACKET_ATTR_TYPE, false, true, false, true, "samplepacket type", SAI_ATTR_VAL_TYPE_S32},
    {SAI_SAMPLEPACKET_ATTR_MODE, false, true, false, true, "samplepacket mode", SAI_ATTR_VAL_TYPE_S32},
    {END_FUNCTIONALITY_ATTRIBS_ID, false, false, false, false, "", SAI_ATTR_VAL_TYPE_UNDETERMINED}
};

static const sai_vendor_attribute_entry_t samplepacket_vendor_attribs[] = {
    SAI_ATTR_CREATE_AND_SET(SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE, sai_samplepacket::samplepacket_attrib_get, sai_samplepacket::samplepacket_attrib_set),
    SAI_ATTR_CREATE_ONLY(SAI_SAMPLEPACKET_ATTR_TYPE, sai_samplepacket::samplepacket_attrib_get),
    SAI_ATTR_CREATE_ONLY(SAI_SAMPLEPACKET_ATTR_MODE, sai_samplepacket::samplepacket_attrib_get)
};

la_status
sai_samplepacket::allocate_samplepacket_instance(uint32_t& samplepacket_instance_id)
{
    return m_samplepacket_db.allocate_id(samplepacket_instance_id);
}

void
sai_samplepacket::free_samplepacket_instance(uint32_t samplepacket_instance_id)
{
    return m_samplepacket_db.release_id(samplepacket_instance_id);
}

#define SAMPLEPACKET_ATTR_GET(attr_id, out_val, in_val)   \
    case attr_id: {                                       \
        set_attr_value(attr_id, out_val, in_val);         \
        break;                                            \
    }

// clang-format on
sai_status_t
sai_samplepacket::samplepacket_attrib_get(_In_ const sai_object_key_t* key,
                                          _Inout_ sai_attribute_value_t* value,
                                          _In_ uint32_t attr_index,
                                          _Inout_ vendor_cache_t* cache,
                                          void* arg)
{
    lsai_object la_samplepacket(key->key.object_id);
    auto sdev = la_samplepacket.get_device();
    const lasai_samplepacket_t* samplepacket = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(la_samplepacket.index);
    if (samplepacket == nullptr) {
        sai_log_error(SAI_API_SAMPLEPACKET, "Unrecognized packet sampling object id 0x%lx", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    if (samplepacket->type == SAI_SAMPLEPACKET_TYPE_SLOW_PATH) {
        // Incase of slow path packet sampling, a mirror session is created to redirect traffic
        // to cpu. Check validity of the mirror session.
        lsai_object la_mirror(samplepacket->slow_path_mirror_session_oid);
        const lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(la_mirror.index);
        if (session == nullptr) {
            sai_log_error(SAI_API_SAMPLEPACKET,
                          "Unrecognized mirror session object associated with packet sampling object id 0x%lx",
                          key->key.object_id);
            return SAI_STATUS_FAILURE;
        }

        if (!session->mirror_cmd_ingress) {
            sai_log_error(SAI_API_SAMPLEPACKET, "Slow path samplepacket oid 0x%lx is unrecognized", key->key.object_id);
            return SAI_STATUS_FAILURE;
        }
    }

    uint32_t attr_id = (uintptr_t)arg;
    switch (attr_id) {
        SAMPLEPACKET_ATTR_GET(SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE, *value, samplepacket->sample_rate);
        SAMPLEPACKET_ATTR_GET(SAI_SAMPLEPACKET_ATTR_TYPE, *value, samplepacket->type);
        SAMPLEPACKET_ATTR_GET(SAI_SAMPLEPACKET_ATTR_MODE, *value, samplepacket->mode);
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_samplepacket::update_sampling_rate_on_all_gress_sample_mirror_instances(uint32_t sample_rate,
                                                                            bool is_ingress_stage,
                                                                            const std::set<sai_object_id_t>& sampled_port_oids)
{
    // On each port where this packet sample object is attached,
    // update device mirror command to reflect change in sampling rate.
    for (auto port_oid : sampled_port_oids) {
        lsai_object port_obj(port_oid);
        auto sdev = port_obj.get_device();
        port_entry* pentry = sdev->m_ports.get_ptr(port_obj.index);
        if (pentry == nullptr) {
            sai_log_error(SAI_API_SAMPLEPACKET, "Unrecognized port object 0x%lx associated with packet sampling object", port_oid);
            return SAI_STATUS_FAILURE;
        }

        const std::set<sai_object_id_t>& sampled_mirror_oids
            = (is_ingress_stage) ? pentry->service.ingress_sample_mirror_oids : pentry->service.egress_sample_mirror_oids;
        for (auto mirror_oid : sampled_mirror_oids) {
            // Using port oid, mirror oid get sample mirror context. The context
            // contains mirror command used for mirror based packet sampling
            // applied on port_oid
            sai_status_t status = sdev->m_mirror_handler->set_sampling_rate_on_sample_mirror_instance(
                port_oid, mirror_oid, is_ingress_stage, sample_rate);
            sai_return_on_error(status, "Error changing sample rate on sample mirror command");
        }
    }

    return SAI_STATUS_SUCCESS;
}

// On all the ports where this packet sampling object is set, get sample mirror sessions
// and update those sample mirror command's sample rate.
sai_status_t
sai_samplepacket::update_sampling_rate_on_all_sample_mirror_objects(lasai_samplepacket_t* samplepacket)
{
    if (samplepacket->type == SAI_SAMPLEPACKET_TYPE_SLOW_PATH) {
        // Slow path packet sample object uses single device mirror command
        // shared across all ports. Its sampling rate does NOT apply to sample mirror objects
        return SAI_STATUS_SUCCESS;
    }

    // On each port and in each direction, where this packet sample object is attached,
    // update device mirror command to reflect change in sampling rate.
    sai_status_t status = update_sampling_rate_on_all_gress_sample_mirror_instances(
        samplepacket->sample_rate, true, samplepacket->ingress_packet_sampled_port_oids);
    sai_return_on_error(status, "Error changing sample rate on sample mirror command applied in ingress direction.");

    status = update_sampling_rate_on_all_gress_sample_mirror_instances(
        samplepacket->sample_rate, true, samplepacket->egress_packet_sampled_port_oids);
    sai_return_on_error(status, "Error changing sample rate on sample mirror command applied in egress direction.");

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_samplepacket::samplepacket_attrib_set(_In_ const sai_object_key_t* key, _In_ const sai_attribute_value_t* value, void* arg)
{

    lsai_object samplepacket_obj(key->key.object_id);
    auto sdev = samplepacket_obj.get_device();
    lasai_samplepacket_t* samplepacket = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(samplepacket_obj.index);
    if (samplepacket == nullptr) {
        sai_log_error(SAI_API_SAMPLEPACKET, "Unrecognized packet sampling object id 0x%lx", key->key.object_id);
        return SAI_STATUS_FAILURE;
    }

    lasai_mirror_session_t* session = nullptr;
    if (samplepacket->type == SAI_SAMPLEPACKET_TYPE_SLOW_PATH) {
        lsai_object mirror_obj(samplepacket->slow_path_mirror_session_oid);
        session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
        if (session == nullptr) {
            sai_log_error(SAI_API_SAMPLEPACKET,
                          "Unrecognized mirror session object associated with packet sampling object id 0x%lx",
                          key->key.object_id);
            return SAI_STATUS_FAILURE;
        }

        if (!session->mirror_cmd_ingress) {
            sai_log_error(SAI_API_SAMPLEPACKET, "samplepacket oid 0x%lx is unrecognized", key->key.object_id);
            return SAI_STATUS_FAILURE;
        }
    }

    uint32_t attr_id = (uintptr_t)arg;
    switch (attr_id) {

    case SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE: {
        samplepacket->sample_rate = get_attr_value(SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE, (*value));
        if (samplepacket->type == SAI_SAMPLEPACKET_TYPE_SLOW_PATH) {
            session->sample_rate = samplepacket->sample_rate;
            la_l2_mirror_command* cmd = static_cast<la_l2_mirror_command*>((la_mirror_command*)session->mirror_cmd_ingress);
            cmd->set_probability((session->sample_rate) ? (1.0 / session->sample_rate) : 0);

            if (sdev->m_use_knet) {
                auto status = sdev->m_knet_sock.send_set_sample_rate(cmd->oid(), session->sample_rate);
                sai_return_on_error(status);
            }

            cmd = static_cast<la_l2_mirror_command*>((la_mirror_command*)session->mirror_cmd_egress);
            cmd->set_probability((session->sample_rate) ? (1.0 / session->sample_rate) : 0);

            if (sdev->m_use_knet) {
                auto status = sdev->m_knet_sock.send_set_sample_rate(cmd->oid(), session->sample_rate);
                sai_return_on_error(status);
            }
        } else {
            // On all the ports where this packet sampling object is set, get sample mirror sessions
            // and update those sample mirror command's sample rate.
            sai_status_t status = update_sampling_rate_on_all_sample_mirror_objects(samplepacket);
            sai_return_on_error(status,
                                "Error in changing sample rate on all sample mirorr commands on all ports where packet sample "
                                "object 0x%lx is attached.",
                                key->key.object_id);
        }
        break;
    }
    case SAI_SAMPLEPACKET_ATTR_TYPE: {
        samplepacket->type = get_attr_value(SAI_SAMPLEPACKET_ATTR_TYPE, (*value));
        break;
    }
    case SAI_SAMPLEPACKET_ATTR_MODE: {
        samplepacket->mode = get_attr_value(SAI_SAMPLEPACKET_ATTR_MODE, (*value));
        break;
    }
    default:
        return SAI_STATUS_NOT_IMPLEMENTED;
        break;
    }
    sai_log_debug(SAI_API_SAMPLEPACKET, "slow path samplepacket's 0x%lx attribute %d updated.", key->key.object_id, attr_id);

    return SAI_STATUS_SUCCESS;
}

std::string
sai_samplepacket::samplepacket_attr_to_string(sai_attribute_t& attr)
{
    std::stringstream log_message;
    auto attrid = (sai_samplepacket_attr_t)attr.id;
    log_message << to_string(attrid) << " ";
    log_message << to_string(attrid, attr.value);
    return log_message.str();
}

sai_status_t
sai_samplepacket::create_slow_path_samplepacket(transaction& txn,
                                                const lsai_object& la_obj,
                                                lasai_mirror_session_t& mirror_session,
                                                lasai_samplepacket_t& samplepacket)
{

    /* Create SAI mirror session to store common data and use with sai mirror apis */
    uint32_t session_instance;
    auto sdev = la_obj.get_device();
    txn.status = sdev->m_mirror_handler->allocate_mirror_session_instance(session_instance);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_mirror_handler->free_mirror_session_instance(session_instance); });

    // create mirror cmd
    la_mac_addr_t mac_addr{};
    la_vlan_tag_tci_t vlan_tag{};
    la_uint_t voq_offset = 0;

    la_l2_mirror_command* mirror_cmd = nullptr;
    mirror_session.sample_rate = samplepacket.sample_rate;
    la_mirror_gid_t ingress_mirror_gid
        = sdev->m_mirror_handler->mirror_session_instance_to_gid(session_instance, true /* is_ingress_stage */);
    txn.status = sdev->m_dev->create_l2_mirror_command(ingress_mirror_gid,
                                                       (la_punt_inject_port*)sdev->m_punt_inject_port,
                                                       mac_addr,
                                                       vlan_tag,
                                                       voq_offset,
                                                       nullptr,
                                                       (mirror_session.sample_rate) ? (1.0 / mirror_session.sample_rate) : 0,
                                                       mirror_cmd);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_dev->destroy(mirror_cmd); });

    mirror_session.mirror_cmd_ingress = mirror_cmd;

    la_l2_mirror_command* mirror_cmd_egress = nullptr;
    la_mirror_gid_t egress_mirror_gid
        = sdev->m_mirror_handler->mirror_session_instance_to_gid(session_instance, false /* is_ingress_stage */);
    txn.status = sdev->m_dev->create_l2_mirror_command(egress_mirror_gid,
                                                       (la_punt_inject_port*)sdev->m_punt_inject_port,
                                                       mac_addr,
                                                       vlan_tag,
                                                       voq_offset,
                                                       nullptr,
                                                       (mirror_session.sample_rate) ? (1.0 / mirror_session.sample_rate) : 0,
                                                       mirror_cmd_egress);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_dev->destroy(mirror_cmd_egress); });

    mirror_session.mirror_cmd_egress = mirror_cmd_egress;

    // clear out list of ports that the mirror session can be attached
    mirror_session.ingress_mirrored_port_oids.clear();
    mirror_session.egress_mirrored_port_oids.clear();

    /* save mirror session */
    lsai_object mirror_object(SAI_OBJECT_TYPE_MIRROR_SESSION, la_obj.switch_id, session_instance);
    mirror_session.session_oid = mirror_object.object_id();
    txn.status = sdev->m_mirror_handler->m_mirror_db.set(session_instance, mirror_session);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_mirror_handler->m_mirror_db.remove(session_instance); });

    /* Store mirror session oid in samplepacket */
    samplepacket.slow_path_mirror_session_oid = mirror_object.object_id();

    /* Add ingress and egress mirror ids to mirror_id to trap map */
    txn.status = sdev->m_trap_manager->add_mirror_id_to_type_map(ingress_mirror_gid, SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_trap_manager->remove_mirror_id_from_type_map(ingress_mirror_gid); });

    txn.status = sdev->m_trap_manager->add_mirror_id_to_type_map(egress_mirror_gid, SAI_HOSTIF_TRAP_TYPE_SAMPLEPACKET);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_trap_manager->remove_mirror_id_from_type_map(egress_mirror_gid); });

    if (sdev->m_use_knet) {
        txn.status = to_la_status(sdev->m_knet_sock.send_set_sample_rate(ingress_mirror_gid, mirror_session.sample_rate));
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { sdev->m_knet_sock.send_remove_sample_rate(ingress_mirror_gid); });

        txn.status = to_la_status(sdev->m_knet_sock.send_set_sample_rate(egress_mirror_gid, mirror_session.sample_rate));
        sai_return_on_la_error(txn.status);
        txn.on_fail([=]() { sdev->m_knet_sock.send_remove_sample_rate(egress_mirror_gid); });
    }

    sai_log_debug(SAI_API_MIRROR,
                  "SDK mirror command 0x%lx for slow path packet sampling created",
                  samplepacket.slow_path_mirror_session_oid);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_samplepacket::create_mirror_type_samplepacket(transaction& txn, lasai_samplepacket_t& samplepacket)
{

    // For packet sampling sessions that uses mirror object/s, at the time of packet sample object
    // creation, there cannot be an association of mirror-session that will be put to use
    // by packet sampling. Hence set it to null oid.
    samplepacket.slow_path_mirror_session_oid = SAI_NULL_OBJECT_ID;

    // Currently mode set/allowed is SAI_SAMPLEPACKET_MODE_EXCLUSIVE. This is the place to
    // support SAI_SAMPLEPACKET_MODE_SHARED in future.
    if (samplepacket.mode != SAI_SAMPLEPACKET_MODE_EXCLUSIVE) {
        sai_log_error(SAI_API_MIRROR, "Packet sampling mode other than exclusive is not supported");
        return SAI_STATUS_NOT_SUPPORTED;
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_samplepacket::create_samplepacket(_Out_ sai_object_id_t* samplepacket_id,
                                      _In_ sai_object_id_t switch_id,
                                      _In_ uint32_t attr_count,
                                      _In_ const sai_attribute_t* attr_list)
{
    transaction txn;
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(SAI_API_SAMPLEPACKET, SAI_OBJECT_TYPE_SWITCH, switch_id, &samplepacket_attr_to_string, "attrs", attrs);

    lasai_mirror_session_t mirror_session;
    lasai_samplepacket_t samplepacket;

    /* Parse attributes */
    get_attrs_value(SAI_SAMPLEPACKET_ATTR_SAMPLE_RATE, attrs, samplepacket.sample_rate, true);
    samplepacket.type = SAI_SAMPLEPACKET_TYPE_SLOW_PATH;
    get_attrs_value(SAI_SAMPLEPACKET_ATTR_TYPE, attrs, samplepacket.type, false);
    samplepacket.mode = SAI_SAMPLEPACKET_MODE_EXCLUSIVE;
    get_attrs_value(SAI_SAMPLEPACKET_ATTR_MODE, attrs, samplepacket.mode, false);

    /* Create SAI samplepacket for storing samplepacket attributes, sai mirror session OID */
    uint32_t samplepacket_instance;
    txn.status = sdev->m_samplepacket_handler->allocate_samplepacket_instance(samplepacket_instance);
    sai_return_on_la_error(txn.status);
    txn.on_fail([=]() { sdev->m_samplepacket_handler->free_samplepacket_instance(samplepacket_instance); });

    if (samplepacket.type == SAI_SAMPLEPACKET_TYPE_SLOW_PATH) {
        // Slow path packet sampling requires mirror session creation. Check for resource availability.
        if (sdev->m_mirror_handler->m_mirror_db.get_free_space() == 0) {
            sai_log_error(SAI_API_MIRROR, "Device mirror session limit reached.");
            return SAI_STATUS_INSUFFICIENT_RESOURCES;
        }

        txn.status
            = to_la_status(sdev->m_samplepacket_handler->create_slow_path_samplepacket(txn, la_obj, mirror_session, samplepacket));
        sai_return_on_la_error(txn.status);
        sai_log_debug(SAI_API_MIRROR, "Packet sampling of type slow path and mode exclusive is created");
    }
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    else if (samplepacket.type == SAI_SAMPLEPACKET_TYPE_MIRROR_SESSION) {
        txn.status = to_la_status(sdev->m_samplepacket_handler->create_mirror_type_samplepacket(txn, samplepacket));
        sai_return_on_la_error(txn.status);
        sai_log_debug(SAI_API_MIRROR, "Packet sampling of type mirror and mode exclusive is created");
    }
#endif

    // This new packet sample object is not attached to any port yet.
    samplepacket.ingress_packet_sampled_port_oids.clear();
    samplepacket.egress_packet_sampled_port_oids.clear();

    /* Store sample packet */
    lsai_object la_samplepacket(SAI_OBJECT_TYPE_SAMPLEPACKET, la_obj.switch_id, samplepacket_instance);
    samplepacket.samplepacket_oid = la_samplepacket.object_id();
    txn.status = sdev->m_samplepacket_handler->m_samplepacket_db.set(samplepacket_instance, samplepacket);
    sai_return_on_la_error(txn.status);

    txn.on_fail([=]() { sdev->m_samplepacket_handler->m_samplepacket_db.remove(samplepacket_instance); });
    *samplepacket_id = la_samplepacket.object_id();
    sai_log_debug(SAI_API_SAMPLEPACKET, "Samplepacket session 0x%lx created", *samplepacket_id);

    return SAI_STATUS_SUCCESS;
}

// samplepacket can be removed once no ports (either in ingress/egress) direction
// use the  for samplepacketing purpose.
sai_status_t
sai_samplepacket::remove_samplepacket(_In_ sai_object_id_t samplepacket_oid)
{
    sai_start_api(
        SAI_API_SAMPLEPACKET, SAI_OBJECT_TYPE_SAMPLEPACKET, samplepacket_oid, &samplepacket_attr_to_string, samplepacket_oid);

    lasai_samplepacket_t* samplepacket = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(la_obj.index);
    if (samplepacket == nullptr) {
        sai_log_error(SAI_API_SAMPLEPACKET, "Unrecognized packet sampling object id 0x%lx", samplepacket_oid);
        return SAI_STATUS_FAILURE;
    }

    if (samplepacket->type == SAI_SAMPLEPACKET_TYPE_SLOW_PATH) {
        lsai_object mirror_obj(samplepacket->slow_path_mirror_session_oid);
        lasai_mirror_session_t* session = sdev->m_mirror_handler->m_mirror_db.get_ptr(mirror_obj.index);
        if (session == nullptr) {
            sai_log_error(SAI_API_SAMPLEPACKET,
                          "Unrecognized mirror session object associated with packet sampling object id 0x%lx",
                          samplepacket_oid);
            return SAI_STATUS_FAILURE;
        }

        if (!session->mirror_cmd_ingress) {
            sai_log_error(SAI_API_SAMPLEPACKET, "Samplepacket oid 0x%lx is unrecognized", samplepacket_oid);
            return SAI_STATUS_FAILURE;
        }

        // check if sample packet object is in use.
        if (samplepacket->ingress_packet_sampled_port_oids.empty() && samplepacket->egress_packet_sampled_port_oids.empty()) {
            // Release sdk mirror command created for sampling packets to cpu.
            la_status lstatus = sdev->m_dev->destroy(session->mirror_cmd_ingress);
            sai_return_on_la_error(lstatus);
        } else {
            // packet sample object is in use.
            sai_log_error(SAI_API_SAMPLEPACKET,
                          "Slow path sample packet instance still in use. Ingress samplepacket attached to ports = %d, Egress "
                          "samplepacket attached to ports = %d",
                          samplepacket->ingress_packet_sampled_port_oids.size(),
                          samplepacket->egress_packet_sampled_port_oids.size());
            return SAI_STATUS_OBJECT_IN_USE;
        }
        // Remove ingress and egress mirror ids from mirror_id to trap map

        la_mirror_gid_t mirror_gid
            = sdev->m_mirror_handler->mirror_session_instance_to_gid(mirror_obj.index, true /* is_ingress_stage */);

        la_status lstatus = sdev->m_trap_manager->remove_mirror_id_from_type_map(mirror_gid);
        sai_return_on_la_error(lstatus);

        if (sdev->m_use_knet) {
            auto status = sdev->m_knet_sock.send_remove_sample_rate(mirror_gid);
            sai_return_on_error(status);
        }

        mirror_gid = sdev->m_mirror_handler->mirror_session_instance_to_gid(mirror_obj.index, false /* is_ingress_stage */);
        lstatus = sdev->m_trap_manager->remove_mirror_id_from_type_map(mirror_gid);
        sai_return_on_la_error(lstatus);

        lstatus = sdev->m_dev->destroy(session->mirror_cmd_egress);
        sai_return_on_la_error(lstatus);

        if (sdev->m_use_knet) {
            auto status = sdev->m_knet_sock.send_remove_sample_rate(mirror_gid);
            sai_return_on_error(status);
        }

        // remove mirror session created for sampling packets to cpu. This will also
        // release mirror session global id used for creating sdk mirror command.
        lstatus = sdev->m_mirror_handler->m_mirror_db.remove(mirror_obj.index);
        sai_return_on_la_error(lstatus);
    }
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
    else if (samplepacket->type == SAI_SAMPLEPACKET_TYPE_MIRROR_SESSION) {
        // Check if the packet sample object is attached to any port
        if (!samplepacket->ingress_packet_sampled_port_oids.empty() || !samplepacket->egress_packet_sampled_port_oids.empty()) {
            // packet sample object is in use.
            sai_log_error(SAI_API_SAMPLEPACKET,
                          "Mirror type sample packet instance still in use. Ingress samplepacket attached to ports = %d, Egress "
                          "samplepacket attached to ports = %d",
                          samplepacket->ingress_packet_sampled_port_oids.size(),
                          samplepacket->egress_packet_sampled_port_oids.size());
            return SAI_STATUS_OBJECT_IN_USE;
        }
    }
#endif

    // remove samplepacket
    la_status lstatus = sdev->m_samplepacket_handler->m_samplepacket_db.remove(la_obj.index);
    sai_return_on_la_error(lstatus);

    sai_log_debug(SAI_API_SAMPLEPACKET, "Samplepacket 0x%lx removed", samplepacket_oid);

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_samplepacket::set_samplepacket_attribute(_In_ sai_object_id_t samplepacket_id, _In_ const sai_attribute_t* attr)
{
    sai_object_key_t key{};
    key.key.object_id = samplepacket_id;
    sai_start_api(SAI_API_SAMPLEPACKET, SAI_OBJECT_TYPE_SAMPLEPACKET, samplepacket_id, &samplepacket_attr_to_string, "attr", *attr);
    char key_str[MAX_KEY_STR_LEN];
    snprintf(key_str, MAX_KEY_STR_LEN, "samplepacket 0x%lx", samplepacket_id);

    return sai_set_attribute(&key, key_str, samplepacket_attribs, samplepacket_vendor_attribs, attr);
}

sai_status_t
sai_samplepacket::get_samplepacket_attribute(_In_ sai_object_id_t samplepacket_id,
                                             _In_ uint32_t attr_count,
                                             _Inout_ sai_attribute_t* attr_list)
{

    sai_object_key_t key{};
    key.key.object_id = samplepacket_id;
    auto attrs = sai_parse_attributes(attr_count, attr_list);
    sai_start_api(
        SAI_API_SAMPLEPACKET, SAI_OBJECT_TYPE_SAMPLEPACKET, samplepacket_id, &samplepacket_attr_to_string, "attrs", attrs);
    char key_str[MAX_KEY_STR_LEN];
    snprintf(key_str, MAX_KEY_STR_LEN, "samplepacket 0x%lx", samplepacket_id);

    return sai_get_attributes(&key, key_str, samplepacket_attribs, samplepacket_vendor_attribs, attr_count, attr_list);
}

const sai_samplepacket_api_t samplepacket_api = {sai_samplepacket::create_samplepacket,
                                                 sai_samplepacket::remove_samplepacket,
                                                 sai_samplepacket::set_samplepacket_attribute,
                                                 sai_samplepacket::get_samplepacket_attribute};

// ---------- Code related to packet sampling using mirror session below ----------------
// These functions have an entry point through sai_port APIs. The functions below
// are invoked when packet sample object and/or sample mirror objects are attached to port.

// For every mirror session objects that is attached to port as sample mirror object
// to be used with packet sampling, create a per port, per mirror, sdk/device mirror
// command and maintain per port map of port_oid to sdk mirror command within
// mirror session context. This function creates device mirror command when a
// a mirror session is attached to port as sample mirror object to be used with packet sampling.
sai_status_t
sai_samplepacket::process_sample_mirror_sessions(std::shared_ptr<lsai_device>& sdev,
                                                 port_lag_common* service,
                                                 bool is_ingress_stage,
                                                 const std::vector<sai_object_id_t>& mirror_session_oids)
{
    // 1. For each of mirror session set as sample mirror session by, create a sample mirror-instance.
    //    (This instance will not have sai object id handle) The cloned sample mirror instance will have
    //    all attributes/properties of mirror session identified by mirror session object.
    //    The reason for not creating object handle for cloned sample mirror-session is that SAI spec
    //    uses regular mirror object id for all sampling operation; viz attaching/detaching to port.
    //
    // 2. Sample mirror instance which is clone of mirror session is not optimized to share
    //    even when all mirror attribues and packet-sampling rate matches with an existing sample
    //    mirror instance that is applied on another port. Implementing an optimized version so as
    //    to share where possible sample mirror instances across both regular mirroring,
    //    packet sample based-mirroring within and across ports is a bit complicated.
    //    The first solution is to blindly clone regular mirror session as a new sample mirror instance
    //    and use it for packet sampling on the port to which they are attached to.
    //
    // Drawback: Due to [2], its possible that sdk mirror command resources can be exhausted. Current
    // requirement/understanding is that NOS is not expected to apply more than one mirror session
    // as sample mirror combined with packet sampling object. Also scale of such packet sampling
    // based combined with mirror session is probably be limited to a few in the order of less than 5.
    // This assumed packet sampling scale will fit into the avaiable mirror command resources provided
    // by silicon.

    for (auto mirror_oid : mirror_session_oids) {
        sai_status_t status
            = sdev->m_mirror_handler->create_sample_mirror_instance_for_port(service->oid, mirror_oid, is_ingress_stage);
        sai_return_on_error(
            status, "Failed to create sample mirror instance corresponding to mirror session object 0x%lx", mirror_oid);
    }

    sai_log_debug(SAI_API_SAMPLEPACKET,
                  "Successfully created %d sample mirror instances corresponding to mirror session objects",
                  mirror_session_oids.size());

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_samplepacket::attach_sample_mirror_session(const std::shared_ptr<lsai_device>& sdev,
                                               port_lag_common* service,
                                               bool is_ingress_stage,
                                               sai_object_id_t packet_sample_oid,
                                               lasai_samplepacket_t* packet_sample,
                                               sai_object_id_t mirror_oid)
{
    // From the mirror object, get corresponding sample-mirror instance.
    lasai_sample_mirror_t sample_mirror_ctx;
    sai_status_t status
        = sdev->m_mirror_handler->get_sample_mirror_context(service->oid, mirror_oid, is_ingress_stage, sample_mirror_ctx);
    sai_return_on_error(status);

    if (sample_mirror_ctx.sample_mirror_cmd == nullptr) {
        sai_log_error(SAI_API_SAMPLEPACKET,
                      "SDK sample mirror command related to mirror 0x%lx and packet sampling object 0x%lx is invalid.",
                      mirror_oid,
                      packet_sample_oid);
        return SAI_STATUS_FAILURE;
    }

    // Adjust sample mirror command's sampling rate to match sampling rate as provided
    // by packet sampling object.
    uint32_t packet_sampling_object_sample_rate = packet_sample->sample_rate;
    la_status lstatus = sample_mirror_ctx.sample_mirror_cmd->set_probability(
        (packet_sampling_object_sample_rate) ? (1.0 / packet_sampling_object_sample_rate) : 0);
    sai_return_on_la_error(
        lstatus,
        "Error updating sample mirror instance to match sampling rate %d mentioned in packet sampling object 0x%lx",
        packet_sampling_object_sample_rate,
        packet_sample_oid);

    // Apply sample mirror instance on all logical ports of the port.
    status = sdev->m_mirror_handler->update_mirror_command_on_port(
        service->oid, is_ingress_stage, sample_mirror_ctx.sample_mirror_cmd, false /* not conditioned */);
    sai_return_on_error(status);

    return SAI_STATUS_SUCCESS;
}

// In two cases sample mirror sessions are applied to device's port.
// case1: When packet sampling object is attached to port for the first time,
//        any previously attached sample mirror sessions will now be
//        bound to device port using sampling rate from packet sampling object
// case2: After having attached packet sampling object to port, when an additional set of
//        sai mirror session objects are attached as sample mirror sessions to use.
// This function uses sampling rate from packet sample object, applies this rate
// to all the cloned/exclusive sample mirror instances and attaches
// on all logical ports of the port.
sai_status_t
sai_samplepacket::attach_sample_mirror_sessions(port_lag_common* service,
                                                bool is_ingress_stage,
                                                sai_object_id_t packet_sample_oid,
                                                const std::vector<sai_object_id_t>& mirror_session_oids)
{
    auto gress = is_ingress_stage ? "ingress" : "egress";
    std::set<sai_object_id_t>* current_sampled_mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        current_sampled_mirror_oid_set = &(service->ingress_sample_mirror_oids);
    } else {
        current_sampled_mirror_oid_set = &(service->egress_sample_mirror_oids);
    }

    lsai_object packetsample_obj(packet_sample_oid);
    auto sdev = packetsample_obj.get_device();
    lasai_samplepacket_t* packet_sample = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(packetsample_obj.index);
    if (packet_sample == nullptr) {
        sai_log_error(SAI_API_SAMPLEPACKET, "Unrecognised %s packet sampling 0x%lx object.", gress, packet_sample_oid);
        return SAI_STATUS_FAILURE;
    }

    for (auto mirror_oid : mirror_session_oids) {
        if (current_sampled_mirror_oid_set->find(mirror_oid) != current_sampled_mirror_oid_set->end()) {
            // if already being sampled, ignore it.
            sai_log_warn(
                SAI_API_SAMPLEPACKET, "Mirror object 0x%lx is already %s sampled on port 0x%lx", mirror_oid, gress, service->oid);
            continue;
        }
        // Program newly added  sample mirror objects on the port using packet smaple objects's sample-rate.
        sai_status_t status
            = attach_sample_mirror_session(sdev, service, is_ingress_stage, packet_sample_oid, packet_sample, mirror_oid);
        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

// In two cases (with or without presence of packet sampling object bound to port)
// sample mirror sessions are removed from device's port. This function disassociates
// sample mirror session instance from all logical ports of the port.
sai_status_t
sai_samplepacket::detach_and_delete_sample_mirror_sessions(const std::shared_ptr<lsai_device>& sdev,
                                                           port_lag_common* service,
                                                           bool is_ingress_stage)
{
    std::set<sai_object_id_t>* current_sampled_mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        current_sampled_mirror_oid_set = &(service->ingress_sample_mirror_oids);
    } else {
        current_sampled_mirror_oid_set = &(service->egress_sample_mirror_oids);
    }

    for (auto mirror_oid : *current_sampled_mirror_oid_set) {
        // Detach all unbound sample mirror objects on the port. Traffic will no more be sampled.
        sai_status_t status = sdev->m_mirror_handler->detach_and_delete_sample_mirror_instance_from_port(
            service->oid, mirror_oid, is_ingress_stage);
        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

// When packet sampling object is removed/detached from port, detach any in-use
// sample mirror sessions. The sample mirror sessions should NOT be deleted.
// They will be deleted when sample mirror sessions are removed/detached from the port.
// By not deleting sample mirror sessions when packet sampling object is removed,
// its possible to re-attach those same sample mirror sessions when a new packet
// sampling object is attached to the port.
sai_status_t
sai_samplepacket::detach_sample_mirror_sessions(const std::shared_ptr<lsai_device>& sdev,
                                                port_lag_common* service,
                                                bool is_ingress_stage)
{
    std::set<sai_object_id_t>* current_sampled_mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        current_sampled_mirror_oid_set = &(service->ingress_sample_mirror_oids);
    } else {
        current_sampled_mirror_oid_set = &(service->egress_sample_mirror_oids);
    }

    for (auto mirror_oid : *current_sampled_mirror_oid_set) {
        // Detach all unbound sample mirror objects on the port. Traffic will no more be sampled.
        sai_status_t status
            = sdev->m_mirror_handler->detach_sample_mirror_instance_from_port(service->oid, mirror_oid, is_ingress_stage);
        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

// When mirror sessions are bound to port as sample mirror instances, this function
// processes those regular mirror session objects and converts them to sample mirror
// instance. Each sample mirror instance uses all attributes of regular mirror
// session object provided but also creates a new device/sdk mirror command
// to be used exclusively for sample mirror session purposes. The reason is
// that sdk sample mirror command will be used to adjust sampling rate to match
// the rate mentioned in packet-sampling object.
sai_status_t
sai_samplepacket::port_sample_mirror_session_set(const sai_object_key_t* key,
                                                 bool is_ingress_stage,
                                                 const std::vector<sai_object_id_t>& new_mirror_session_oids_to_sample)
{

    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();

    port_lag_common* service = nullptr;
    la_status lstatus = sai_port_get_service(sdev, key->key.object_id, service);
    sai_return_on_la_error(lstatus);

    if (service == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    auto gress = is_ingress_stage ? "ingress" : "egress";
    std::set<sai_object_id_t>* current_sampled_mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        current_sampled_mirror_oid_set = &(service->ingress_sample_mirror_oids);
    } else {
        current_sampled_mirror_oid_set = &(service->egress_sample_mirror_oids);
    }

    if (!new_mirror_session_oids_to_sample.empty()) {
        // A list of mirror session objects are attached to port as sample mirror sessions
        // Using list of regular mirror sessions (mirror_session_oids) create mirror instance with
        // its own sdk mirror command to be used with packet sampling.
        sai_status_t status = process_sample_mirror_sessions(sdev, service, is_ingress_stage, new_mirror_session_oids_to_sample);
        sai_return_on_error(
            status,
            "Error creating sample mirror sessions on port 0x%lx. No resources left to create sample mirror session",
            service->oid);

        if ((is_ingress_stage && service->ingress_packet_sample_oid != SAI_NULL_OBJECT_ID)
            || (!is_ingress_stage && service->egress_packet_sample_oid != SAI_NULL_OBJECT_ID)) {
            auto packet_sample_oid = (is_ingress_stage) ? service->ingress_packet_sample_oid : service->egress_packet_sample_oid;
            // Using rate from packet sample oid, modify per port cloned mirror sessions
            // to use sampling rate from packet-sample-oid and attach to all logical ports.
            status = attach_sample_mirror_sessions(service, is_ingress_stage, packet_sample_oid, new_mirror_session_oids_to_sample);
            if (status != SAI_STATUS_SUCCESS) {
                // Remove any sample mirror instances created for each mirror session object meant to be used
                // for packet sampling and mirroring in call process_sample_mirror_sessions().
                for (auto mirror_oid : new_mirror_session_oids_to_sample) {
                    sdev->m_mirror_handler->detach_and_delete_sample_mirror_instance_from_port(
                        key->key.object_id, mirror_oid, is_ingress_stage);
                }
            }

            sai_return_on_error(status, "Error attaching all %s sample mirror sessions on port 0x%lx", gress, key->key.object_id);
        }

        // update port entry to reflect changes related to mirroring.
        // add new mirror-oids to port entry that the port is mirroring.
        for (auto oid : new_mirror_session_oids_to_sample) {
            current_sampled_mirror_oid_set->insert(oid);
        }

    } else if (new_mirror_session_oids_to_sample.empty()) {
        sai_status_t status = detach_and_delete_sample_mirror_sessions(sdev, service, is_ingress_stage);
        sai_return_on_error(status, "Error deleting sample mirror sessions from port 0x%lx.", service->oid);
        // clear mirror-oid set since all mirrors are detached.
        current_sampled_mirror_oid_set->clear();
    }

    auto operation = new_mirror_session_oids_to_sample.empty() ? "Detached" : "Attached";
    sai_log_debug(SAI_API_SAMPLEPACKET,
                  "%s %s sample mirror session/s associated with port sampling object 0x%lx",
                  operation,
                  gress,
                  key->key.object_id);
    return SAI_STATUS_SUCCESS;
}

// A new packet sampling object is attached to port. If there are any sample
// mirror instances already attached on this port, program the device to apply
// sample mirror instances with sampling rate matching rate mentioned in
// packet sampling object.
sai_status_t
sai_samplepacket::attach_packet_sample_instance(port_lag_common* service, bool is_ingress_stage, sai_object_id_t packet_sample_oid)
{
    auto gress = is_ingress_stage ? "ingress" : "egress";
    lsai_object packetsample_obj(packet_sample_oid);
    auto sdev = packetsample_obj.get_device();
    lasai_samplepacket_t* packet_sample = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(packetsample_obj.index);
    if (packet_sample == nullptr) {
        sai_log_error(SAI_API_SAMPLEPACKET, "Unrecognised %s packet sampling 0x%lx object.", gress, packet_sample_oid);
        return SAI_STATUS_FAILURE;
    }

    std::set<sai_object_id_t>* mirror_oid_set = nullptr;
    if (is_ingress_stage) {
        mirror_oid_set = &(service->ingress_sample_mirror_oids);
    } else {
        mirror_oid_set = &(service->egress_sample_mirror_oids);
    }

    // Program all existing sample mirror objects already applied on the port using
    // packet sample object's sample-rate
    for (auto mirror_oid : *mirror_oid_set) {
        sai_status_t status
            = attach_sample_mirror_session(sdev, service, is_ingress_stage, packet_sample_oid, packet_sample, mirror_oid);
        sai_return_on_error(status);
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t
sai_samplepacket::port_packet_sampling_set(const sai_object_key_t* key, bool is_ingress_stage, sai_object_id_t packet_sample_oid)
{

    lsai_object port_obj(key->key.object_id);
    auto sdev = port_obj.get_device();

    port_lag_common* service = nullptr;
    la_status lstatus = sai_port_get_service(sdev, key->key.object_id, service);
    sai_return_on_la_error(lstatus);

    if (service == nullptr) {
        return SAI_STATUS_SUCCESS;
    }

    auto gress = is_ingress_stage ? "ingress" : "egress";
    sai_object_id_t current_sample_oid
        = (is_ingress_stage) ? service->ingress_packet_sample_oid : service->egress_packet_sample_oid;
    if (packet_sample_oid != SAI_NULL_OBJECT_ID) {
        // Attempt to attach new packet sampling to port.
        if (current_sample_oid != SAI_NULL_OBJECT_ID) {
            // A sampling session already attached to port. Cannot attach second one.
            sai_log_error(SAI_API_SAMPLEPACKET,
                          "Unable to set %s packet sampling 0x%lx object to port. A packet sampling oid 0xlx already attached",
                          gress,
                          packet_sample_oid,
                          current_sample_oid);
            return SAI_STATUS_FAILURE;
        }

        lsai_object packetsample_obj(packet_sample_oid);
        lasai_samplepacket_t* packet_sample = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(packetsample_obj.index);
        if (packet_sample == nullptr) {
            sai_log_error(SAI_API_SAMPLEPACKET,
                          "Unable to set %s packet sampling 0x%lx object to port. Unknown packet sampling oid",
                          gress,
                          packet_sample_oid);
            return SAI_STATUS_FAILURE;
        }

        if (packet_sample->type == SAI_SAMPLEPACKET_TYPE_SLOW_PATH) {
            // At the time of packet sampling object creation, in case of SAI_SAMPLEPACKET_TYPE_SLOW_PATH,
            // a mirror session is also created. Use the mirror session and attach to the port.
            if (packet_sample->slow_path_mirror_session_oid == SAI_NULL_OBJECT_ID) {
                sai_log_error(SAI_API_SAMPLEPACKET,
                              "Unable to set slow path packet sampling object to port 0x%lx. Invalid packet sampling object",
                              packet_sample_oid);
                return SAI_STATUS_FAILURE;
            }
            sai_status_t status = sdev->m_mirror_handler->attach_slow_path_packet_sampling(
                key->key.object_id, is_ingress_stage, packet_sample->slow_path_mirror_session_oid);
            sai_return_on_error(status);
        }
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
        if (packet_sample->type == SAI_SAMPLEPACKET_TYPE_MIRROR_SESSION) {
            // At the time of packet sampling object creation of type SAI_SAMPLEPACKET_TYPE_MIRROR_SESSION,
            // check any sampling mirror session/s set on the port. If set, apply those
            // sampling mirror session/s but rate of sampling matching rate mentioned in
            // in packet sampling object.
            sai_status_t status = attach_packet_sample_instance(service, is_ingress_stage, packet_sample_oid);
            sai_return_on_error(status);
            auto sample_mirror_session_count
                = (is_ingress_stage) ? service->ingress_sample_mirror_oids.size() : service->egress_sample_mirror_oids.size();
            if (sample_mirror_session_count) {
                sai_log_debug(
                    SAI_API_SAMPLEPACKET,
                    "A set of %d %s sample mirror sessions attached on port 0x%lx with sampling rate equal to rate of packet "
                    "sampling object 0x%lx",
                    sample_mirror_session_count,
                    gress,
                    service->oid,
                    packet_sample_oid);
            }
        }
#endif

        // Update list of ports on which this sample packet object is attached to.
        if (is_ingress_stage) {
            packet_sample->ingress_packet_sampled_port_oids.insert(service->oid);
        } else {
            packet_sample->egress_packet_sampled_port_oids.insert(service->oid);
        }

    } else {
        if (current_sample_oid == SAI_NULL_OBJECT_ID) {
            // No sampling packet session to detach.
            sai_log_warn(SAI_API_SAMPLEPACKET,
                         "No %s packet sampling object attached to port 0xlx that can be removed.",
                         gress,
                         key->key.object_id);
            return SAI_STATUS_SUCCESS;
        }

        // Detach any existing packet sampling already attached on port.
        lsai_object packetsample_obj(current_sample_oid);
        lasai_samplepacket_t* packet_sample = sdev->m_samplepacket_handler->m_samplepacket_db.get_ptr(packetsample_obj.index);
        if (packet_sample != nullptr) {
            if (packet_sample->type == SAI_SAMPLEPACKET_TYPE_SLOW_PATH) {
                sai_status_t status = sdev->m_mirror_handler->detach_slow_path_packet_sampling(
                    key->key.object_id, is_ingress_stage, packet_sample->slow_path_mirror_session_oid);
                sai_return_on_error(status);
            }
#if CURRENT_SAI_VERSION_CODE > SAI_VERSION_CODE(1, 5, 2)
            if (packet_sample->type == SAI_SAMPLEPACKET_TYPE_MIRROR_SESSION) {
                // If there are any sample mirror sessions in progress, detach them from all
                // logical ports. The sdk/device sample mirror command itself should not be
                // destroyed. A packet sampling object can be re-attached at which time,
                // sample mirror sessions will be applied on logical ports again using
                // new sampling rate from new packet sampling object.
                sai_status_t status = detach_sample_mirror_sessions(sdev, service, is_ingress_stage);
                sai_return_on_error(status);
            }
#endif
        } else {
            sai_log_error(SAI_API_SAMPLEPACKET,
                          "Unable to remove %s packet sampling 0x%lx object from port. Unknown packet sampling oid",
                          gress,
                          packet_sample_oid);
            return SAI_STATUS_FAILURE;
        }

        // Update list of ports on which this sample packet object is attached to.
        if (is_ingress_stage) {
            packet_sample->ingress_packet_sampled_port_oids.erase(service->oid);
        } else {
            packet_sample->egress_packet_sampled_port_oids.erase(service->oid);
        }
    }

    // Update port entry packet sampling oid to reflect the new operation.
    if (is_ingress_stage) {
        service->ingress_packet_sample_oid = packet_sample_oid;
    } else {
        service->egress_packet_sample_oid = packet_sample_oid;
    }

    return SAI_STATUS_SUCCESS;
}
}
}
