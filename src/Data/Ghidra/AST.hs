{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
module Data.Ghidra.AST
  ( Address(..), AddressSpace(..), AddressSpaceType(..)
  , PcodeOpAST(..), VarnodeAST(..)
  , SequenceNumber(..), SequenceTime
  ) where

import GHC.Generics     (Generic)
import Data.Aeson       (FromJSON(..), ToJSON(..), Options(..)
                        , genericParseJSON, genericToJSON, defaultOptions)
import Data.Char        (toLower)
import Data.List        (stripPrefix)
import Data.Hashable    (Hashable(..))
import Text.Printf      (PrintfArg, printf)

import Data.Ghidra.PcodeTypes (PcodeOpType)
import Data.PrettyShow        (PrettyShow(..), Repr(..), TermColorCode(..)
                              , TermSGR(..), TermMod(MBold), TermColor(NoColor)
                              , fcolorb, treset, (#<>), (#*<>))
import qualified Data.Text as T

lowerFirst :: String -> String
lowerFirst = \case
  [] -> []
  ch : rest -> toLower ch : rest

standardOpts :: String -> Options
standardOpts pref = defaultOptions
  { fieldLabelModifier = \old -> maybe old lowerFirst $ stripPrefix pref old }

data AddressSpaceType = REGISTER | STACK | UNIQUE | RAM | CONST
  deriving (Show, Read, Eq, Ord, Enum, Generic)
instance Hashable AddressSpaceType
instance FromJSON AddressSpaceType where
  parseJSON = genericParseJSON (defaultOptions
    { constructorTagModifier = map toLower})
instance ToJSON AddressSpaceType where
  toJSON = genericToJSON (defaultOptions
    { constructorTagModifier = map toLower})
instance PrettyShow AddressSpaceType where
  prettyShow spc =
    let color = case spc of
                  REGISTER -> Green
                  STACK -> Blue
                  UNIQUE -> Black
                  RAM -> Brown
                  CONST -> Magenta
     in fcolorb color #<> Repr spc #<> treset

data VarnodeAST = VarnodeAST
  { varnodeAddress    :: Address
  , varnodeDef        :: Maybe SequenceNumber
  , varnodeUniqueId   :: Int
  , varnodeSize       :: Int
  , varnodeAddrTied   :: Bool
  , varnodeFree       :: Bool
  , varnodeHash       :: Bool
  , varnodeInput      :: Bool
  , varnodePersistant :: Bool
  , varnodeRegister   :: Bool
  , varnodeUnaffected :: Bool
  , varnodeUnique     :: Bool
  } deriving (Show, Read, Eq, Generic)
instance FromJSON VarnodeAST where
  parseJSON = genericParseJSON (standardOpts "varnode")
instance ToJSON VarnodeAST where
  toJSON = genericToJSON (standardOpts "varnode")
instance PrettyShow VarnodeAST where
  prettyShow vnode = TermSGR [MBold] NoColor
    #*<> "("
    #<> treset
    #<> varnodeAddress vnode
    #*<> " : "
    #<> Repr (varnodeSize vnode)
    #<> TermSGR [MBold] NoColor
    #<> (case varnodeDef vnode of
      Just def -> T.pack $ printf " -> %04x" $ seqTime def
      Nothing -> "")
    #*<> ")"
    #<> treset
  prettyShowList lst = T.intercalate (T.pack " ") <$> mapM prettyShow lst

data PcodeOpAST = PcodeOpAST
  { pcodeDead     :: Bool
  , pcodeInputs   :: [VarnodeAST]
  , pcodeMnemonic :: PcodeOpType
  , pcodeSeqnum   :: SequenceNumber
  , pcodeOutput   :: Maybe VarnodeAST
  } deriving (Show, Read, Eq, Generic)
instance FromJSON PcodeOpAST where
  parseJSON = genericParseJSON (standardOpts "pcode")
instance ToJSON PcodeOpAST where
  toJSON = genericToJSON (standardOpts "pcode")
instance PrettyShow PcodeOpAST where
  prettyShow op = do
    output <- maybe (pure "--") prettyShow $ pcodeOutput op
    T.pack (printf "%08x %04x " (addrOffset $ seqTarget $ pcodeSeqnum op) $
        seqTime $ pcodeSeqnum op)
      #<> output
      #*<> " "
      #<> Repr (pcodeMnemonic op)
      #*<> " "
      #<> pcodeInputs op
  prettyShowList lst = T.intercalate (T.pack "\n") <$> mapM prettyShow lst

newtype SequenceTime = SequenceTime { unSequenceTime :: Int }
  deriving (Show, Read, Eq, Ord, Num, Hashable, FromJSON, ToJSON, PrintfArg)

data SequenceNumber = SequenceNumber
  { seqOrder  :: Int
  , seqTime   :: SequenceTime
  , seqTarget :: Address
  } deriving (Show, Read, Eq, Ord, Generic)
instance Hashable SequenceNumber
instance FromJSON SequenceNumber where
  parseJSON = genericParseJSON (standardOpts "seq")
instance ToJSON SequenceNumber where
  toJSON = genericToJSON (standardOpts "seq")

data Address = Address
  { addrAddressSpace :: AddressSpaceType
  , addrOffset       :: Integer
  } deriving (Show, Read, Eq, Ord, Generic)
instance Hashable Address
instance FromJSON Address where
  parseJSON = genericParseJSON (standardOpts "addr")
instance ToJSON Address where
  toJSON = genericToJSON (standardOpts "addr")
instance PrettyShow Address where
  prettyShow addr = addrAddressSpace addr
    #*<> ":"
    #*<> T.pack (printf "%08x" $ addrOffset addr)

data AddressSpace = AddressSpace
  { addrBaseSpaceID :: Int
  , addrName        :: AddressSpaceType
  } deriving (Show, Read, Eq, Generic)
instance FromJSON AddressSpace where
  parseJSON = genericParseJSON (standardOpts "addr")
instance ToJSON AddressSpace where
  toJSON = genericToJSON (standardOpts "addr")
