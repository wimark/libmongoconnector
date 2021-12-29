package libmongoconnector

import (
	"fmt"
	"strings"

	"github.com/globalsign/mgo/bson"
	wimark "github.com/wimark/libwimark"
)

// GetSimpleMaskQuery simple UUID mask
func GetSimpleMaskQuery(mask wimark.SimpleMask) bson.M {
	var out = bson.M{}

	if mask.UUID != nil {
		out["_id"] = bson.M{
			"$in": mask.UUID,
		}
	}

	return out
}

// GetTimestampMaskQuery timestamp query
func GetTimestampMaskQuery(v wimark.TimestampMask) bson.M {
	var out = bson.M{}

	if v.UUID != nil {
		out["_id"] = bson.M{
			"$in": v.UUID,
		}
	}

	if v.Start != nil && v.Stop != nil {
		out["timestamp"] = bson.M{
			"$gt": v.Start,
			"$lt": v.Stop,
		}
	} else if v.Start != nil {
		out["timestamp"] = bson.M{
			"$gt": v.Start,
		}
	}

	return out
}

// GetWlanMaskQuery WLAN query
func GetWlanMaskQuery(mask wimark.WLANMask) bson.M {
	var q = []bson.M{}

	if mask.UUID != nil {
		q = append(q, bson.M{
			"_id": bson.M{
				"$in": mask.UUID,
			},
		})
	}

	if mask.HasRadius != nil {
		var radiusMask = bson.M{
			"$in": mask.HasRadius,
		}

		q = append(q, bson.M{
			"radiusacctservers": radiusMask,
		})

		q = append(q, bson.M{
			"security.data.radiusauthentication": radiusMask,
		})
	}

	if mask.HasL2Chains != nil {
		var l2chains = bson.M{
			"$in": mask.HasL2Chains,
		}

		q = append(q, bson.M{
			"firewall.l2_chain": l2chains,
		})
	}

	if mask.HasCaptiveRedirects != nil {
		var cr = bson.M{
			"$in": mask.HasCaptiveRedirects,
		}

		q = append(q, bson.M{
			"guestcontrol.captive_redirect": cr,
		})
	}

	if mask.HasHotspotProfiles != nil {
		var hsMask = bson.M{
			"$in": mask.HasHotspotProfiles,
		}

		q = append(q, bson.M{
			"security.data.hotspot20_profile": hsMask,
		})
	}

	var out = bson.M{}
	if len(q) > 0 {
		out["$or"] = q
	}

	return out
}

func cpeQueryFromSerial(serial string) string {

	return fmt.Sprintf("%x-%s-%x-%x",
		"a"+serial[0:3], serial[3:7], serial[7:9], serial[9:11])
}

// GetCpeMaskQuery CPE mask query
func GetCpeMaskQuery(mask wimark.CPEMask) bson.M {
	var q = []bson.M{}

	if mask.UUID != nil {
		q = append(q, bson.M{
			"_id": bson.M{"$in": mask.UUID},
		})
	}

	if mask.HasWLANs != nil {
		q = append(q, bson.M{
			"config.wifi.wlans": bson.M{"$in": mask.HasWLANs},
		})
	}

	if mask.HasL2Chains != nil {
		q = append(q, bson.M{
			"config.firewall.l2_chain": bson.M{"$in": mask.HasL2Chains},
		})
	}

	if mask.HasCaptiveRedirects != nil {
		var cr = bson.M{
			"$in": mask.HasCaptiveRedirects,
		}
		q = append(q, bson.M{
			"config.wired.vlans.guest_control.captive_redirect": cr,
		})
	}

	if mask.HasController != nil {
		var regexes []string
		for _, serial := range mask.HasController {
			regexes = append(regexes, cpeQueryFromSerial(serial))
		}
		q = append(q, bson.M{
			"_id": bson.M{"$regex": strings.Join(regexes, "|")},
		})
	}

	var out = bson.M{}
	if len(q) > 0 {
		out["$or"] = q
	}

	if mask.Connected != nil {
		return bson.M{
			"$and": []bson.M{out, {"connected": *mask.Connected}},
		}
	}

	return out
}

// GetCPEModelMaskQuery query
func GetCPEModelMaskQuery(mask wimark.CPEModelMask) bson.M {
	var q = []bson.M{}

	if mask.UUID != nil {
		q = append(q, bson.M{
			"_id": bson.M{"$in": mask.UUID},
		})
	}

	if mask.Names != nil {
		q = append(q, bson.M{
			"name": bson.M{"$in": mask.Names},
		})
	}

	var out = bson.M{}
	if len(q) > 0 {
		out["$or"] = q
	}
	return out
}

// GetConfigRuleMaskQuery query
func GetConfigRuleMaskQuery(mask wimark.ConfigRuleMask) bson.M {
	var q = []bson.M{}

	if mask.UUID != nil {
		q = append(q, bson.M{
			"_id": bson.M{"$in": mask.UUID},
		})
	}

	if mask.WLANs != nil {
		var wlanMask = bson.M{"$in": mask.WLANs}

		q = append(q, bson.M{"template.wlans": wlanMask})
		q = append(q, bson.M{"template.cpe_config_template.wifi.wlans": wlanMask})
	}

	if mask.HasL2Chains != nil {
		var chainMask = bson.M{"$in": mask.HasL2Chains}
		q = append(q, bson.M{"template.cpe_config_template.firewall.l2_chain": chainMask})
	}

	if mask.Auto != nil || mask.Always != nil || mask.CPEs != nil || mask.Models != nil {

		var qTmpl = bson.M{}
		var constr = []bson.M{
			{"model": "", "cpes": bson.M{"$size": 0}},
		}

		if mask.Auto != nil {
			qTmpl["is_auto"] = *mask.Auto
		}
		if mask.Always != nil {
			qTmpl["is_always"] = *mask.Always
		}
		if mask.CPEs != nil {
			constr = append(constr, bson.M{
				"cpes": bson.M{"$in": mask.CPEs},
			})
		}
		if mask.Models != nil {
			constr = append(constr, bson.M{
				"model": bson.M{"$in": mask.Models},
			})
		}
		if len(constr) != 0 {
			qTmpl["$or"] = constr
		}

		q = append(q, qTmpl)
	}

	var out = bson.M{}
	if len(q) != 0 {
		out["$or"] = q
	}
	return out
}

// GetControllerMask controller mask
func GetControllerMask(mask wimark.ControllerMask) bson.M {
	var q = []bson.M{}

	if mask.UUID != nil {
		q = append(q, bson.M{
			"_id": bson.M{"$in": mask.UUID},
		})
	}

	if mask.Enabled != nil {
		q = append(q, bson.M{
			"enable": *mask.Enabled,
		})
	}

	var out = bson.M{}
	if len(q) > 0 {
		out["$or"] = q
	}
	return out
}

// GetEventMaskQuery event mask
func GetEventMaskQuery(mask wimark.EventMask) bson.M {
	var out = GetTimestampMaskQuery(mask.TimestampMask)

	if mask.Type != nil {
		out["type"] = bson.M{
			"$in": mask.Type,
		}
	}

	if mask.Subject_id != nil {
		out["subject_id"] = bson.M{
			"$in": mask.Subject_id,
		}
	}

	if mask.Level != nil {
		out["level"] = bson.M{
			"$in": mask.Level,
		}
	}
	return out
}

// GetClientStatMaskQuery client stat mask
func GetClientStatMaskQuery(mask wimark.ClientStatMask) bson.M {
	var out = GetTimestampMaskQuery(mask.TimestampMask)

	if mask.CPE != nil {
		out["cpe"] = bson.M{
			"$in": mask.CPE,
		}
	}

	if mask.CallingStationId != nil {
		out["callingstationid"] = bson.M{
			"$in": mask.CallingStationId,
		}
	}
	return out
}

// GetStatsMaskQuery stat mask
func GetStatsMaskQuery(mask wimark.StatsMask) bson.M {
	var q = []bson.M{}

	if mask.UUID != nil {
		q = append(q, bson.M{
			"_id": bson.M{
				"$in": mask.UUID,
			},
		})
	}

	if mask.CPEUUID != nil {
		q = append(q, bson.M{
			"cpe": bson.M{
				"$in": mask.CPEUUID,
			},
		})
	}

	if mask.Start != nil && mask.Stop != nil {
		q = append(q, bson.M{
			"timestamp": bson.M{
				"$gt": mask.Start,
				"$lt": mask.Stop,
			},
		})
	} else if mask.Start != nil {
		q = append(q, bson.M{
			"timestamp": bson.M{
				"$gt": mask.Start,
			},
		})
	}
	var out = bson.M{}
	if len(q) > 0 {
		out["$and"] = q
	}
	return out
}

// GetLBSClientDataMaskQuery lbs mask
func GetLBSClientDataMaskQuery(mask wimark.LBSClientDataMask) bson.M {
	var out = GetTimestampMaskQuery(mask.TimestampMask)

	if mask.CPE != nil {
		out["cpe"] = bson.M{
			"$in": mask.CPE,
		}
	}

	if mask.Radio != nil {
		out["radio"] = bson.M{
			"$in": mask.Radio,
		}
	}

	if mask.ClientMac != nil {
		out["clientmac"] = bson.M{
			"$in": mask.ClientMac,
		}
	}

	if mask.RSSI != nil {
		out["rssi"] = bson.M{
			"$in": mask.RSSI,
		}
	}
	return out
}

// GetLBSCPEInfoMaskQuery lbs cpe info mask
func GetLBSCPEInfoMaskQuery(mask wimark.LBSCPEInfoMask) bson.M {
	var out = GetSimpleMaskQuery(mask.SimpleMask)

	if mask.CPE != nil {
		out["cpe"] = bson.M{
			"$in": mask.CPE,
		}
	}

	if mask.Group != nil {
		out["group"] = bson.M{
			"$in": mask.Group,
		}
	}

	if mask.Name != nil {
		out["name"] = bson.M{
			"$in": mask.Name,
		}
	}

	if mask.X.Upper != nil && mask.X.Lower != nil {
		var v = bson.M{}
		if mask.X.Upper != nil {
			v["$lte"] = mask.X.Upper
		}
		if mask.X.Lower != nil {
			v["$gte"] = mask.X.Lower
		}
		out["x"] = v
	}

	if mask.Y.Upper != nil && mask.Y.Lower != nil {
		var v = bson.M{}
		if mask.Y.Upper != nil {
			v["$lte"] = mask.Y.Upper
		}
		if mask.Y.Lower != nil {
			v["$gte"] = mask.Y.Lower
		}
		out["y"] = v
	}
	if mask.Z.Upper != nil && mask.Z.Lower != nil {
		var v = bson.M{}
		if mask.Z.Upper != nil {
			v["$lte"] = mask.Z.Upper
		}
		if mask.Z.Lower != nil {
			v["$gte"] = mask.Z.Lower
		}
		out["z"] = v
	}
	return out
}

// GetLBSClientCoordsMaskQuery lbs client coord mask
func GetLBSClientCoordsMaskQuery(mask wimark.LBSClientCoordsMask) bson.M {
	var out = GetTimestampMaskQuery(mask.TimestampMask)

	if mask.Group != nil {
		out["group"] = bson.M{
			"$in": mask.Group,
		}
	}

	if mask.Mac != nil {
		out["mac"] = bson.M{
			"$in": mask.Mac,
		}
	}

	if mask.X.Upper != nil && mask.X.Lower != nil {
		var v = bson.M{}
		if mask.X.Upper != nil {
			v["$lte"] = mask.X.Upper
		}
		if mask.X.Lower != nil {
			v["$gte"] = mask.X.Lower
		}
		out["x"] = v
	}

	if mask.Y.Upper != nil && mask.Y.Lower != nil {
		var v = bson.M{}
		if mask.Y.Upper != nil {
			v["$lte"] = mask.Y.Upper
		}
		if mask.Y.Lower != nil {
			v["$gte"] = mask.Y.Lower
		}
		out["y"] = v
	}
	if mask.Z.Upper != nil && mask.Z.Lower != nil {
		var v = bson.M{}
		if mask.Z.Upper != nil {
			v["$lte"] = mask.Z.Upper
		}
		if mask.Z.Lower != nil {
			v["$gte"] = mask.Z.Lower
		}
		out["z"] = v
	}
	return out
}
