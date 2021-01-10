{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DeriveGeneric #-}
module Data.Ghidra.Nodes
  (Pcode(..), PcodeNode(..), Function(..)) where

import Control.Arrow    (second)
import Control.Monad    (liftM2, liftM3)
import Data.Aeson       (FromJSON(..))
import Data.Aeson.Types (Parser, parseFail)
import Data.List        (uncons)
import Data.Maybe       (listToMaybe)
import Data.Text        (Text)
import GHC.Generics     (Generic)

import Data.PrettyShow (PrettyShow(..))
import Data.Ghidra.AST (PcodeOpAST(..), VarnodeAST(..), Address(..)
                       , AddressSpaceType(CONST))
import Data.Ghidra.PcodeTypes (PcodeOpType(..))

import qualified Data.Text as T

type Expect ast a = (String, ast -> Maybe a)

expectP :: Expect PcodeOpAST a -> PcodeOpAST -> Parser a
expectP (expLabel, conv) op =
  maybe (parseFail $ show (pcodeMnemonic op) <> ": expected " <> expLabel)
    pure $ conv op

expectV :: Expect VarnodeAST a -> VarnodeAST -> Parser a
expectV (expLabel, conv) op =
  maybe (parseFail $ "expected " <> expLabel <> " in varnode") pure $ conv op

output :: Expect PcodeOpAST VarnodeAST
output = ("output", pcodeOutput)

noOutput :: Expect PcodeOpAST ()
noOutput = ("no output", maybe (Just ()) (const Nothing) . pcodeOutput)

inp1 :: Expect PcodeOpAST VarnodeAST
inp1 = ("one input argument", (\case
  [x] -> Just x
  _ -> Nothing) . pcodeInputs)

inp1p :: Expect PcodeOpAST (VarnodeAST, [VarnodeAST])
inp1p = ("at least one input argument", uncons . pcodeInputs)

inp2 :: Expect PcodeOpAST (VarnodeAST, VarnodeAST)
inp2 = ("two input arguments", (\case
  [x, y] -> Just (x, y)
  _ -> Nothing) . pcodeInputs)

inp3 :: Expect PcodeOpAST (VarnodeAST, VarnodeAST, VarnodeAST)
inp3 = ("two input arguments", (\case
  [x, y, z] -> Just (x, y, z)
  _ -> Nothing) . pcodeInputs)

constant :: Expect VarnodeAST Integer
constant = ("constant", \vn ->
  if addrAddressSpace (varnodeAddress vn) == CONST
     then Just $ addrOffset $ varnodeAddress vn
     else Nothing)

data PcodeNode =
    NodeUnimplemented
  | NodeCopy VarnodeAST VarnodeAST          -- v0 = v1
  | NodeLoad Integer VarnodeAST VarnodeAST  -- v0 = *[id]v1
  | NodeStore Integer VarnodeAST VarnodeAST -- *[id]v0 <- v1
  | NodeBranch VarnodeAST                   -- goto v0
  | NodeCBranch VarnodeAST VarnodeAST       -- if (v1) goto v0
  | NodeBranchInd VarnodeAST                -- goto [v0]
  | NodeCall VarnodeAST [VarnodeAST]        -- call v0, *v1
  | NodeCallInd VarnodeAST [VarnodeAST]     -- call [v0], *v1
  | NodeReturn VarnodeAST (Maybe VarnodeAST)   -- return [v0] (with value v1)
  | NodeIntEqual      VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 == v2
  | NodeIntNotEqual   VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 != v2
  | NodeIntSLess      VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 s< v2
  | NodeIntSLessEqual VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 s<= v2
  | NodeIntLess       VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 < v2
  | NodeIntLessEqual  VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 <= v2
  | NodeIntZext       VarnodeAST VarnodeAST            -- v0 = zext(v1)
  | NodeIntSext       VarnodeAST VarnodeAST            -- v0 = sext(v1)
  | NodeIntAdd        VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 + v2
  | NodeIntSub        VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 - v2
  | NodeIntCarry      VarnodeAST VarnodeAST VarnodeAST -- v0 = carry(v1, v2)
  | NodeIntSCarry     VarnodeAST VarnodeAST VarnodeAST -- v0 = scarry(v1, v2)
  | NodeIntSBorrow    VarnodeAST VarnodeAST VarnodeAST -- v0 = sborrow(v1, v2)
  | NodeInt2Comp      VarnodeAST VarnodeAST            -- v0 = -v1
  | NodeIntNegate     VarnodeAST VarnodeAST            -- v0 = ~v1
  | NodeIntXor        VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 ^ v2
  | NodeIntAnd        VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 & v2
  | NodeIntOr         VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 | v2
  | NodeIntLeft       VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 << v2
  | NodeIntRight      VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 >> v2
  | NodeIntSRight     VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 s>> v2
  | NodeIntMult       VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 * v2
  | NodeIntDiv        VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 / v2
  | NodeIntSDiv       VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 s/ v2
  | NodeIntRem        VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 % v2
  | NodeIntSRem       VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 s% v2
  | NodeBoolXor       VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 ^^ v2
  | NodeBoolAnd       VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 && v2
  | NodeBoolOr        VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 || v2
  | NodeMultiEqual    VarnodeAST [VarnodeAST]          -- v0 = v1...vn
  | NodeIndirect VarnodeAST VarnodeAST Integer    -- v0 = v1 (indirect iop)
  | NodePiece    VarnodeAST VarnodeAST VarnodeAST -- v0 = v1 <|> v2
  | NodeSubPiece VarnodeAST VarnodeAST Integer    -- v0 = v1(int)
  | NodeCast     VarnodeAST VarnodeAST            -- v0 = v1
  | NodePtrAdd   VarnodeAST VarnodeAST VarnodeAST Integer -- v0 = v1[v2] (with sz)
  | NodePtrSub   VarnodeAST VarnodeAST VarnodeAST  -- v0 = v1 + v2
  deriving (Show, Eq, Read)
instance FromJSON PcodeNode where
  parseJSON val = parseJSON val >>= parsePcodeOp

data Pcode = Pcode
  { pcodeNode :: PcodeNode
  , pcodeAST :: PcodeOpAST
  }
  deriving (Show, Eq, Read)
instance FromJSON Pcode where
  parseJSON val = do
    ast <- parseJSON val
    node <- parsePcodeOp ast
    pure $ Pcode node ast
instance PrettyShow Pcode where
  prettyShow (Pcode _ ast) = prettyShow ast
  prettyShowList lst = T.intercalate (T.pack "\n") <$> mapM prettyShow lst


expectUnaryOp :: (VarnodeAST -> VarnodeAST -> PcodeNode) ->
  PcodeOpAST -> Parser PcodeNode
expectUnaryOp typ op = liftM2 typ (expectP output op) (expectP inp1 op)

expectBinOp :: (VarnodeAST -> VarnodeAST -> VarnodeAST -> PcodeNode) ->
  PcodeOpAST -> Parser PcodeNode
expectBinOp typ op = do
  out <- expectP output op
  (in1, in2) <- expectP inp2 op
  pure $ typ out in1 in2

parsePcodeOp :: PcodeOpAST -> Parser PcodeNode
parsePcodeOp op =
  case pcodeMnemonic op of
    UNIMPLEMENTED -> pure NodeUnimplemented
    COPY -> expectUnaryOp NodeCopy op
    LOAD -> do
      (cid, ptr) <- expectP inp2 op
      liftM3 NodeLoad (expectV constant cid) (expectP output op) (pure ptr)
    STORE -> do
      expectP noOutput op
      (cid, dst, src) <- expectP inp3 op
      cid' <- expectV constant cid
      pure $ NodeStore cid' dst src
    BRANCH    -> expectP noOutput op >> NodeBranch <$> expectP inp1 op
    CBRANCH   -> expectP noOutput op >> uncurry NodeCBranch <$> expectP inp2 op
    BRANCHIND -> expectP noOutput op >> NodeBranchInd <$> expectP inp1 op
    CALL      -> uncurry NodeCall <$> expectP inp1p op
    CALLIND   -> uncurry NodeCallInd <$> expectP inp1p op
    RETURN    -> uncurry NodeReturn . second listToMaybe <$> expectP inp1p op
    INT_EQUAL      -> expectBinOp NodeIntEqual op
    INT_NOTEQUAL   -> expectBinOp NodeIntNotEqual op
    INT_SLESS      -> expectBinOp NodeIntSLess op
    INT_SLESSEQUAL -> expectBinOp NodeIntSLessEqual op
    INT_LESS       -> expectBinOp NodeIntLess op
    INT_LESSEQUAL  -> expectBinOp NodeIntLessEqual op
    INT_ZEXT    -> expectUnaryOp NodeIntZext op
    INT_SEXT    -> expectUnaryOp NodeIntSext op
    INT_ADD     -> expectBinOp   NodeIntAdd op
    INT_SUB     -> expectBinOp   NodeIntSub op
    INT_CARRY   -> expectBinOp   NodeIntCarry op
    INT_SCARRY  -> expectBinOp   NodeIntSCarry op
    INT_SBORROW -> expectBinOp   NodeIntSBorrow op
    INT_2COMP   -> expectUnaryOp NodeInt2Comp op
    INT_NEGATE  -> expectUnaryOp NodeIntNegate op
    INT_XOR     -> expectBinOp   NodeIntXor op
    INT_AND     -> expectBinOp   NodeIntAnd op
    INT_OR      -> expectBinOp   NodeIntOr op
    INT_LEFT    -> expectBinOp   NodeIntLeft op
    INT_RIGHT   -> expectBinOp   NodeIntRight op
    INT_SRIGHT  -> expectBinOp   NodeIntSRight op
    INT_MULT    -> expectBinOp   NodeIntMult op
    INT_DIV     -> expectBinOp   NodeIntDiv op
    INT_SDIV    -> expectBinOp   NodeIntSDiv op
    INT_REM     -> expectBinOp   NodeIntRem op
    INT_SREM    -> expectBinOp   NodeIntSRem op
    BOOL_XOR    -> expectBinOp   NodeBoolXor op
    BOOL_AND    -> expectBinOp   NodeBoolAnd op
    BOOL_OR     -> expectBinOp   NodeBoolOr  op
    -- TODO: floating
    MULTIEQUAL  ->
      liftM2 NodeMultiEqual (expectP output op) (pure $ pcodeInputs op)
    INDIRECT  -> do
      (val, iop) <- expectP inp2 op
      liftM3 NodeIndirect (expectP output op) (pure val) (expectV constant iop)
    PIECE     -> expectBinOp NodePiece op
    SUBPIECE  -> do
      (val, bits) <- expectP inp2 op
      liftM3 NodeSubPiece (expectP output op) (pure val) (expectV constant bits)
    CAST      -> expectUnaryOp NodeCast op
    PTRADD    -> do
      (base, ind, sz) <- expectP inp3 op
      out <- expectP output op
      NodePtrAdd out base ind <$> expectV constant sz
    PTRSUB    -> expectBinOp NodePtrSub op
    _ -> parseFail $ "Unsupported opcode: " <> show (pcodeMnemonic op)

data Function = Function
  { name    :: Text
  , address :: Address
  , pcodes  :: [Pcode]
  }
  deriving (Read, Show, Eq, Generic)
instance FromJSON Function
