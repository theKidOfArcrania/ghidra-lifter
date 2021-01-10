module Data.Ghidra
  ( module Data.Ghidra.AST
  , module Data.Ghidra.Nodes
  , PcodeOpType(..)
  , decodePcodes
  ) where

import Data.Aeson      (decode)
import Data.Ghidra.AST
import Data.Ghidra.Nodes
import Data.Ghidra.PcodeTypes (PcodeOpType(..))
import qualified Data.ByteString.Lazy as B

decodePcodes :: B.ByteString -> Maybe [PcodeOpAST]
decodePcodes = decode


