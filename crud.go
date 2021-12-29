package libmongoconnector

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	mongo "github.com/wimark/libmongo"
	wimark "github.com/wimark/libwimark"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

// UnitFactory represents a factory function that
// creates type-erased objects. It is used to mimic generic behaviour.
type UnitFactory func() interface{}

// ModelInfo is information required by CRUD functions
type ModelInfo struct {
	Coll        string
	Indexes     []mgo.Index
	ToMongoFn   func(json.RawMessage) (bson.M, error)
	FromMongoFn func(bson.M) (json.RawMessage, error)
	MaskF       func(json.RawMessage) (bson.M, error)
}

func getSimpleTimestampIndex(expiration *time.Duration) mgo.Index {
	var v mgo.Index
	v.Key = []string{"timestamp"}
	if expiration != nil {
		v.ExpireAfter = *expiration
	}
	return v
}

func simpleMaskF(in json.RawMessage) (bson.M, error) {
	var mask wimark.SimpleMask
	if err := json.Unmarshal(in, &mask); err != nil {
		return nil, err
	}

	return GetSimpleMaskQuery(mask), nil
}

// ModelMap is a mapping between model type name in JSON
// and corresponding ModelInfo (e.g. {"cpe": libwimark.CPE})
type ModelMap map[string]ModelInfo

func toMongoViaFactory(v json.RawMessage,
	dataPtr interface{}) (bson.M, error) {
	if err := json.Unmarshal(v, dataPtr); err != nil {
		return nil, err
	}

	var tmp, err = bson.Marshal(dataPtr)
	if err != nil {
		return nil, err
	}

	var out = bson.M{}
	if err := bson.Unmarshal(tmp, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func fromMongoViaFactory(v bson.M,
	dataPtr interface{}) (json.RawMessage, error) {
	var tmp, err1 = bson.Marshal(v)
	if err1 != nil {
		return nil, err1
	}

	if err := bson.Unmarshal(tmp, dataPtr); err != nil {
		return nil, err
	}

	var out, err2 = json.Marshal(dataPtr)
	if err2 != nil {
		return nil, err2
	}

	return out, nil
}

func timestampMaskF(in json.RawMessage) (bson.M, error) {
	var mask wimark.TimestampMask
	if err := json.Unmarshal(in, &mask); err != nil {
		return nil, err
	}

	return GetTimestampMaskQuery(mask), nil
}

// GenericFactories for return factories
func GenericFactories() ModelMap {
	var expiration = time.Duration(3) * time.Duration(24) * time.Hour
	return ModelMap{
		"wlan": ModelInfo{
			Coll: "wlans",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.WLAN{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.WLAN{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.WLANMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetWlanMaskQuery(mask), nil
			},
		},
		"cpe": ModelInfo{
			Coll: "cpes",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.CPE{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.CPE{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.CPEMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetCpeMaskQuery(mask), nil
			},
		},
		"stat": ModelInfo{
			Coll: "stats",
			Indexes: []mgo.Index{
				getSimpleTimestampIndex(&expiration),
			},
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.Stat{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.Stat{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.StatsMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetStatsMaskQuery(mask), nil
			},
		},
		"client-stat": ModelInfo{
			Coll: "client_stats",
			Indexes: []mgo.Index{
				getSimpleTimestampIndex(&expiration),
			},
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.ClientStat{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.ClientStat{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.ClientStatMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetClientStatMaskQuery(mask), nil
			},
		},
		"stat-event-rule": ModelInfo{
			Coll: "stat_event_rule",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.StatEventRule{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.StatEventRule{})
			},
			MaskF: simpleMaskF,
		},
		"poll-cpe": ModelInfo{
			Coll: "poll_cpe",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.CPEPollSettings{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.CPEPollSettings{})
			},
			MaskF: simpleMaskF,
		},
		"event": ModelInfo{
			Coll: "events",
			Indexes: []mgo.Index{
				getSimpleTimestampIndex(&expiration),
			},
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.SystemEvent{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.SystemEvent{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.EventMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetEventMaskQuery(mask), nil
			},
		},
		"radius": ModelInfo{
			Coll: "radius",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.Radius{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.Radius{})
			},
			MaskF: simpleMaskF,
		},
		"lbs-cpe-info": ModelInfo{
			Coll: "lbs_cpe_info",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.LBSCPEInfo{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.LBSCPEInfo{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.LBSCPEInfoMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetLBSCPEInfoMaskQuery(mask), nil
			},
		},
		"lbs_zones": ModelInfo{
			Coll: "lbs_zones",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.LBSZone{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.LBSZone{})
			},
			MaskF: simpleMaskF,
		},
		"lbs-client-data": ModelInfo{
			Coll: "lbs_client_data",
			Indexes: []mgo.Index{
				getSimpleTimestampIndex(&expiration),
			},
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.LBSClientData{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.LBSClientData{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.LBSClientDataMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetLBSClientDataMaskQuery(mask), nil
			},
		},
		"lbs-client-coords": ModelInfo{
			Coll: "lbs_client_coords",
			Indexes: []mgo.Index{
				getSimpleTimestampIndex(&expiration),
			},
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.LBSClientCoords{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.LBSClientCoords{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.LBSClientCoordsMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetLBSClientCoordsMaskQuery(mask), nil
			},
		},
		"client-addr": ModelInfo{
			Coll: "client_addr",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.ClientAddr{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.ClientAddr{})
			},
			MaskF: simpleMaskF,
		},
		"vpn-host": ModelInfo{
			Coll: "vpn_host",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.VPNHost{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.VPNHost{})
			},
			MaskF: simpleMaskF,
		},
		"cpe-scan-data": ModelInfo{
			Coll: "cpe_scan_data",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.CPEScanData{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.CPEScanData{})
			},
			MaskF: simpleMaskF,
		},
		"cpe-model": ModelInfo{
			Coll: "cpe_model",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.CPEModel{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.CPEModel{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.CPEModelMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetCPEModelMaskQuery(mask), nil
			},
		},
		"config-rule": ModelInfo{
			Coll: "config_rule",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.ConfigRule{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.ConfigRule{})
			},
			MaskF: func(in json.RawMessage) (bson.M, error) {
				var mask wimark.ConfigRuleMask
				if err := json.Unmarshal(in, &mask); err != nil {
					return nil, err
				}
				return GetConfigRuleMaskQuery(mask), nil
			},
		},
		"l2-chain": ModelInfo{
			Coll: "l2_chains",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.L2Chain{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.L2Chain{})
			},
			MaskF: simpleMaskF,
		},
		"captive-redirect": ModelInfo{
			Coll: "captive_redirects",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.CaptiveRedirect{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.CaptiveRedirect{})
			},
			MaskF: simpleMaskF,
		},
		"hotspot-profile": ModelInfo{
			Coll: "hotspot_profile",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.Hotspot20Profile{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.Hotspot20Profile{})
			},
			MaskF: simpleMaskF,
		},
		"controller": ModelInfo{
			Coll: "controllers",
			ToMongoFn: func(v json.RawMessage) (bson.M, error) {
				return toMongoViaFactory(v, &wimark.Controller{})
			},
			FromMongoFn: func(v bson.M) (json.RawMessage, error) {
				return fromMongoViaFactory(v, &wimark.Controller{})
			},
			MaskF: simpleMaskF,
		},
	}
}

// ErasedRequest is the alias for 'any' type used for processing incoming requests
type ErasedRequest interface{}

// ErasedRequestFactory fot factory
type ErasedRequestFactory func() ErasedRequest

// ActionCB  See BaseCB
type ActionCB func(ErasedRequest, ModelInfo) (interface{}, []wimark.ModelError)

func makeDBError(e wimark.ModelError) wimark.ModelError {
	e.Module = wimark.ModuleDB
	return e
}

// BaseCB General callback for all MQTT broker incoming messages. Uses actionCB
// for useful side effects.
func BaseCB(
	payload []byte,
	requestUnitFactory ErasedRequestFactory,
	m ModelMap,
	actionCB ActionCB,
) wimark.Document {
	var reqDoc = wimark.Document{}
	var err = json.Unmarshal(payload, &reqDoc)
	if err != nil {
		return wimark.Document{
			"errors": []wimark.ModelError{
				makeDBError(wimark.ModelError{
					Type:        wimark.WimarkErrorCodeJson,
					Description: fmt.Sprintf("JSON parse failed: %s", err),
				}),
			},
		}
	}

	var data = wimark.Document{}
	var errors = []wimark.ModelError{}
	for t, contents := range reqDoc {
		var t = t
		var modelInfo, ok = m[t]
		if !ok {
			errors = append(errors, makeDBError(wimark.ModelError{
				Type:        wimark.WimarkErrorCodeDB,
				Description: fmt.Sprintf("Invalid data request model: %s", t),
				Object:      t}))
			continue
		}
		var rspT = ErasedRequest(requestUnitFactory())
		var s, _ = json.Marshal(contents)
		var err = json.Unmarshal(s, rspT)
		if err != nil {
			errors = append(errors, makeDBError(wimark.ModelError{
				Type:        wimark.WimarkErrorCodeJson,
				Description: fmt.Sprintf("JSON parse failed: %s", err),
				Object:      t}))
			continue
		}

		var actionErrors []wimark.ModelError
		data[t], actionErrors = actionCB(rspT, modelInfo)

		for _, e := range actionErrors {
			e.Object = t
			errors = append(errors, e)
		}
	}

	return wimark.Document{
		"data":   data,
		"errors": errors,
	}
}

// OperationCB ...
type OperationCB func(*mongo.MongoDb, *log.Logger,
	[]byte, ModelMap) wimark.Document

// CreateCB Callback for creation.
func CreateCB(db *mongo.MongoDb,
	payload []byte, m ModelMap) wimark.Document {
	type Request map[wimark.UUID]json.RawMessage

	return BaseCB(payload,
		func() ErasedRequest {
			return &Request{}
		}, m,
		func(reqErased ErasedRequest,
			m_info ModelInfo) (interface{}, []wimark.ModelError) {
			var reqP, _ = reqErased.(*Request)
			var req = *reqP

			var errorList = []wimark.ModelError{}
			var data = []wimark.UUID{}
			var docs = []interface{}{}
			for id, e := range req {
				if len(id) == 0 {
					errorList = append(errorList, makeDBError(wimark.ModelError{
						Type:        wimark.WimarkErrorCodeDB,
						Description: "Id cannot be empty",
						ObjectId:    id,
					}))
					continue
				}

				var doc, docErr = m_info.ToMongoFn(e)
				if docErr != nil {
					errorList = append(errorList, makeDBError(wimark.ModelError{
						Type:        wimark.WimarkErrorCodeDB,
						Description: docErr.Error(),
						ObjectId:    id,
					}))
					continue
				}
				doc["_id"] = id

				docs = append(docs, doc)
			}

			var insertErr error
			db.SessExec(func(sess *mgo.Session) {
				var bulk = sess.DB("").C(m_info.Coll).Bulk()
				bulk.Unordered()
				bulk.Insert(docs...)
				_, insertErr = bulk.Run()
			})

			if insertErr != nil {
				errorList = append(errorList, makeDBError(wimark.ModelError{
					Type:        wimark.WimarkErrorCodeDB,
					Description: insertErr.Error(),
				}))
			}

			return data, errorList
		})
}

// FindData as main map for mask finding
type FindData map[wimark.UUID]json.RawMessage

// ReadCB Callback for search.
func ReadCB(db *mongo.MongoDb, payload []byte, m ModelMap) wimark.Document {
	return BaseCB(payload,
		func() ErasedRequest {
			return &json.RawMessage{}
		}, m,
		func(reqErased ErasedRequest,
			m_info ModelInfo) (interface{}, []wimark.ModelError) {
			var reqP = reqErased.(*json.RawMessage)
			var req = *reqP

			var errors = []wimark.ModelError{}

			var query, queryErr = m_info.MaskF(json.RawMessage(req))
			if queryErr != nil {
				errors = append(errors, makeDBError(wimark.ModelError{
					Type: wimark.WimarkErrorCodeDB,
					Description: fmt.Sprintf("Failed to parse query: %s",
						queryErr.Error()),
				}))
			}

			var reply = []bson.M{}
			var data = FindData{}
			if err := db.Find(m_info.Coll, query, &reply); err != nil {
				errors = append(errors, makeDBError(wimark.ModelError{
					Type:        wimark.WimarkErrorCodeDB,
					Description: err.Error(),
				}))
			} else {
				for _, doc := range reply {
					var idErased, ok = doc["_id"]
					if !ok {
						errors = append(errors, makeDBError(wimark.ModelError{
							Type:        wimark.WimarkErrorCodeDB,
							Description: "Document has no ID. This should never happen.",
						}))
						continue
					}
					var id = wimark.UUID(fmt.Sprint(idErased))
					var j, err = m_info.FromMongoFn(doc)
					if err != nil {
						errors = append(errors, makeDBError(wimark.ModelError{
							Type:        wimark.WimarkErrorCodeDB,
							Description: err.Error(),
							ObjectId:    id,
						}))
						continue
					}

					data[id] = j
				}
			}

			return data, errors
		})
}

// DeleteCB Callback for removal.
func DeleteCB(db *mongo.MongoDb, payload []byte, m ModelMap) wimark.Document {
	return BaseCB(payload,
		func() ErasedRequest {
			return &json.RawMessage{}
		}, m,
		func(reqErased ErasedRequest,
			m_info ModelInfo) (interface{}, []wimark.ModelError) {
			var reqP = reqErased.(*json.RawMessage)
			var req = *reqP

			var errors = []wimark.ModelError{}

			var query, queryErr = m_info.MaskF(json.RawMessage(req))
			if queryErr != nil {
				errors = append(errors, makeDBError(wimark.ModelError{
					Type: wimark.WimarkErrorCodeDB,
					Description: fmt.Sprintf("Failed to parse query: %s",
						queryErr.Error()),
				}))
			}

			var ids = []wimark.UUID{}
			{
				var tmp = []struct {
					V string `bson:"_id"`
				}{}

				var err error
				db.SessExec(func(sess *mgo.Session) {
					err = sess.DB("").C(m_info.Coll).
						Find(query).Select(bson.M{"_id": 1}).All(&tmp)
				})
				if err != nil {
					errors = append(errors, wimark.ModelError{
						Type:        wimark.WimarkErrorCodeDB,
						Description: err.Error()})
				}
				for _, e := range tmp {
					ids = append(ids, wimark.UUID(e.V))
				}
			}
			var data = []wimark.UUID{}
			for _, id := range ids {
				if err := db.Remove(m_info.Coll, string(id)); err != nil && err != mgo.ErrNotFound {
					errors = append(errors, wimark.ModelError{
						Type:        wimark.WimarkErrorCodeDB,
						Description: err.Error(),
						ObjectId:    id,
					})
					continue
				}
			}

			return data, errors
		})
}

// UpdateCB Callback for update.
func UpdateCB(db *mongo.MongoDb,
	payload []byte, m ModelMap) wimark.Document {
	type Request map[wimark.UUID]wimark.Document

	return BaseCB(payload,
		func() ErasedRequest {
			return &Request{}
		}, m,
		func(reqErased ErasedRequest,
			m_info ModelInfo) (interface{}, []wimark.ModelError) {
			var reqP, _ = reqErased.(*Request)
			var req = *reqP

			var data = []wimark.UUID{}
			var errList = []wimark.ModelError{}

			for id, patch := range req {
				var doc bson.M

				var findOk = db.FindByID(m_info.Coll, string(id), &doc)
				if !findOk {
					errList = append(errList, wimark.ModelError{
						Type:        wimark.WimarkErrorCodeDB,
						Description: "Entry with this ID not found in DB",
						ObjectId:    id,
					})
					continue
				}

				var j json.RawMessage
				{
					var err error
					if j, err = m_info.FromMongoFn(doc); err != nil {
						errList = append(errList, wimark.ModelError{
							Type:        wimark.WimarkErrorCodeJson,
							Description: err.Error(),
							ObjectId:    id,
						})
						continue
					}
				}
				var jDoc = wimark.Document{}
				if err := json.Unmarshal(j, &jDoc); err != nil {
					errList = append(errList, wimark.ModelError{
						Type:        wimark.WimarkErrorCodeJson,
						Description: err.Error(),
						ObjectId:    id,
					})
					continue
				}

				for k, v := range patch {
					jDoc[k] = v
				}

				var newBDoc json.RawMessage
				{
					var err error
					newBDoc, err = json.Marshal(jDoc)
					if err != nil {
						errList = append(errList, wimark.ModelError{
							Type:        wimark.WimarkErrorCodeJson,
							Description: err.Error(),
							ObjectId:    id,
						})
						continue
					}
				}

				var newDoc bson.M
				{
					var err error
					if newDoc, err = m_info.ToMongoFn(
						json.RawMessage(newBDoc)); err != nil {
						errList = append(errList, wimark.ModelError{
							Type:        wimark.WimarkErrorCodeDB,
							Description: err.Error(),
							ObjectId:    id,
						})
						continue
					}
				}

				var updateOk = db.Update(m_info.Coll, id, newDoc)
				if updateOk != nil {
					errList = append(errList, wimark.ModelError{
						Type:        wimark.WimarkErrorCodeDB,
						Description: "Mongo update error",
						ObjectId:    id,
					})
					continue
				}

			}

			return data, errList
		})
}
