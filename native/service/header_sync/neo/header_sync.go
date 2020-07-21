/*
 * Copyright (C) 2020 The poly network Authors
 * This file is part of The poly network library.
 *
 * The  poly network  is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The  poly network  is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * You should have received a copy of the GNU Lesser General Public License
 * along with The poly network .  If not, see <http://www.gnu.org/licenses/>.
 */

package neo

import (
	"crypto/sha256"
	"fmt"
	"github.com/polynetwork/poly/native"
	hscommon "github.com/polynetwork/poly/native/service/header_sync/common"

	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/genesis"
	"github.com/polynetwork/poly/core/types"
	"github.com/polynetwork/poly/native/service/utils"
)

type NEOHandler struct {
}

func NewNEOHandler() *NEOHandler {
	return &NEOHandler{}
}

func (this *NEOHandler) SyncGenesisHeader(native *native.NativeService) error {
	params := new(hscommon.SyncGenesisHeaderParam)
	if err := params.Deserialization(common.NewZeroCopySource(native.GetInput())); err != nil {
		return fmt.Errorf("SyncGenesisHeader, contract params deserialize error: %v", err)
	}
	// get operator from database
	operatorAddress, err := types.AddressFromBookkeepers(genesis.GenesisBookkeepers)
	if err != nil {
		return err
	}
	//check witness
	err = utils.ValidateOwner(native, operatorAddress)
	if err != nil {
		return fmt.Errorf("SyncGenesisHeader, checkWitness error: %v", err)
	}
	// Deserialize neo block header
	header := new(NeoBlockHeader)
	if err := header.Deserialization(common.NewZeroCopySource(params.GenesisHeader)); err != nil {
		return fmt.Errorf("SyncGenesisHeader, deserialize header err: %v", err)
	}
	if neoConsensus, _ := getConsensusValByChainId(native, params.ChainID); neoConsensus == nil {
		// Put NeoConsensus.NextConsensus into storage
		if err = putConsensusValByChainId(native, &NeoConsensus{
			ChainID:       params.ChainID,
			Height:        header.Index,
			NextConsensus: header.NextConsensus,
		}); err != nil {
			return fmt.Errorf("SyncGenesisHeader, update ConsensusPeer error: %v", err)
		}
	}
	return nil
}

func (this *NEOHandler) SyncBlockHeader(native *native.NativeService) error {
	params := new(hscommon.SyncBlockHeaderParam)
	if err := params.Deserialization(common.NewZeroCopySource(native.GetInput())); err != nil {
		return fmt.Errorf("SyncBlockHeader, contract params deserialize error: %v", err)
	}
	return processHeadersAndMsg(native, params.ChainID, params.Headers, nil)
}

func processHeadersAndMsg(native *native.NativeService, chainId uint64, headers [][]byte, msg *NeoCrossChainMsg) error {
	neoConsensus, err := getConsensusValByChainId(native, chainId)
	if err != nil {
		return fmt.Errorf("ProcessHeadersAndMsg, the consensus validator has not been initialized, chainId: %d", chainId)
	}
	msgVerified := false
	if msg == nil {
		msgVerified = true
	}
	newNeoConsensus := &NeoConsensus{
		neoConsensus.ChainID,
		neoConsensus.Height,
		neoConsensus.NextConsensus,
	}
	previousConsensus := &NeoConsensus{
		neoConsensus.ChainID,
		neoConsensus.Height,
		neoConsensus.NextConsensus,
	}
	for _, v := range headers {
		header := new(NeoBlockHeader)
		if err := header.Deserialization(common.NewZeroCopySource(v)); err != nil {
			return fmt.Errorf("ProcessHeadersAndMsg, NeoBlockHeaderFromBytes error: %v", err)
		}
		if !header.NextConsensus.Equals(newNeoConsensus.NextConsensus) && header.Index > newNeoConsensus.Height {
			if err = verifyHeader(header, newNeoConsensus); err != nil {
				return fmt.Errorf("ProcessHeadersAndMsg, verifyHeader error: %v", err)
			}
			previousConsensus = newNeoConsensus
			newNeoConsensus = &NeoConsensus{
				ChainID:       newNeoConsensus.ChainID,
				Height:        header.Index,
				NextConsensus: header.NextConsensus,
			}
		}
	}
	if newNeoConsensus.Height > neoConsensus.Height {
		if err = putConsensusValByChainId(native, newNeoConsensus); err != nil {
			return fmt.Errorf("ProcessHeadersAndMsg, update ConsensusPeer error: %v", err)
		}
	}
	if !msgVerified && msg != nil {
		if msg.Index < newNeoConsensus.Height {
			return fmt.Errorf("ProcessHeadersAndMsg, state root in msg is not at current consensus epoch, msg.Index: %d, consensus switch height: %d", msg.Index, newNeoConsensus.Height)
		}
		if msg.Index == newNeoConsensus.Height {
			if err := verifyCrossChainMsg(native, msg, previousConsensus); err != nil {
				return fmt.Errorf("ProcessHeadersAndMsg, verifyCrossChainMsg error: %v, msg.Index: %d, consensus.Height: %d", err, msg.Index, previousConsensus.Height)
			}
			// update the cross chain message hash in order to process other txs in same block
			msgBs, err := msg.GetMessage()
			if err != nil {
				return fmt.Errorf("ProcessHeadersAndMsg, msg.GetMessage() error: %v", err)
			}
			if err := putMsgHash(native, chainId, sha256.Sum256(msgBs)); err != nil {
				return fmt.Errorf("ProcessHeadersAndMsg, putMsgHash error: %v", err)
			}
		} else {
			if err := verifyCrossChainMsg(native, msg, newNeoConsensus); err != nil {
				return fmt.Errorf("ProcessHeadersAndMsg, verifyCrossChainMsg error: %v, msg.Index: %d, consensus.Height: %d", err, msg.Index, newNeoConsensus.Height)
			}
		}
		msgVerified = true
	}
	if !msgVerified {
		return fmt.Errorf("ProcessHeadersAndMsg, verify cross chain message failed")
	}
	return nil
}

func (this *NEOHandler) SyncCrossChainMsg(native *native.NativeService) error {
	return nil
}
