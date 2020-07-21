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
	"fmt"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/native"
	scom "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/polynetwork/poly/native/service/governance/side_chain_manager"
	"github.com/polynetwork/poly/native/service/header_sync/neo"
)

type NEOHandler struct {
}

func NewNEOHandler() *NEOHandler {
	return &NEOHandler{}
}

func (this *NEOHandler) MakeDepositProposal(service *native.NativeService) (*scom.MakeTxParam, error) {
	params := new(scom.EntranceParam)
	if err := params.Deserialization(common.NewZeroCopySource(service.GetInput())); err != nil {
		return nil, fmt.Errorf("neo MakeDepositProposal, contract params deserialize error: %v", err)
	}
	// Deserialize neo cross chain msg and verify its signature
	crossChainMsg := new(neo.NeoCrossChainMsg)
	if err := crossChainMsg.Deserialization(common.NewZeroCopySource(params.HeaderOrCrossChainMsg)); err != nil {
		return nil, fmt.Errorf("neo MakeDepositProposal, deserialize crossChainMsg error: %v", err)
	}
	// Parse Neo headers from params.Extra to 2-d byte array
	headers := make([][]byte, 0)
	if len(params.Extra) > 0 {
		extraSource := common.NewZeroCopySource(params.Extra)
		extraLen, eof := extraSource.NextVarUint()
		if eof {
			return nil, fmt.Errorf("neo MakeDepositProposal, deserialize headers from Extra error")
		}
		for i := 0; uint64(i) < extraLen; i++ {
			headerBs, eof := extraSource.NextVarBytes()
			if eof {
				return nil, fmt.Errorf("neo MakeDepositProposal, NextVarBytes for header bytes error")
			}
			headers = append(headers, headerBs)
		}
	}
	// Passing headers and Verify crossChainMsg, Neo consensus peers will be updated if headers are valid
	if err := neo.VerifyCrossChainMsgSig(service, params.SourceChainID, crossChainMsg, headers); err != nil {
		return nil, fmt.Errorf("neo MakeDepositProposal, VerifyCrossChainMsg error: %v", err)
	}
	// Verify the validity of proof with the help of state root in verified neo cross chain msg
	sideChain, err := side_chain_manager.GetSideChain(service, params.SourceChainID)
	if err != nil {
		return nil, fmt.Errorf("neo MakeDepositProposal, side_chain_manager.GetSideChain error: %v", err)
	}
	value, err := verifyFromNeoTx(params.Proof, crossChainMsg, sideChain.CCMCAddress)
	if err != nil {
		return nil, fmt.Errorf("neo MakeDepositProposal, VerifyFromNeoTx error: %v", err)
	}
	// Ensure the tx has not been processed before, and mark the tx as processed
	if err := scom.CheckDoneTx(service, value.CrossChainID, params.SourceChainID); err != nil {
		return nil, fmt.Errorf("neo MakeDepositProposal, check done transaction error:%s", err)
	}
	if err = scom.PutDoneTx(service, value.CrossChainID, params.SourceChainID); err != nil {
		return nil, fmt.Errorf("neo MakeDepositProposal, putDoneTx error:%s", err)
	}
	return value, nil
}
