{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{- HLINT ignore PrettyShowConfig -}
module Data.PrettyShow where

import Control.Monad.Trans.Reader (Reader, runReader, ask)
import Data.Text (Text)
import qualified Data.Text as T
newtype Repr a = Repr { unRepr :: a }


data PrettyShowConfig  = PrettyShowConfig
  { hasTerm :: Bool
  }

defaultShow :: PrettyShowConfig
defaultShow = PrettyShowConfig
  { hasTerm = True }

type PShowing = Reader PrettyShowConfig Text

class PrettyShow a where
  prettyShow :: a -> PShowing

  prettyShowList :: [a] -> PShowing
  prettyShowList lst = T.pack . show <$> mapM prettyShow lst
  {-# INLINE prettyShowList #-}

pshow :: PrettyShow a => PrettyShowConfig -> a -> Text
pshow cfg = pshowWith cfg . prettyShow
{-# INLINE pshow #-}

pshowWith :: PrettyShowConfig -> PShowing -> Text
pshowWith = flip runReader
{-# INLINE pshowWith #-}

instance (Show a) => PrettyShow (Repr a) where
  prettyShow = pure . T.pack . show . unRepr
  {-# INLINE prettyShow #-}

instance PrettyShow a => PrettyShow [a] where
  prettyShow = prettyShowList
  {-# INLINE prettyShow #-}

instance PrettyShow Text where
  prettyShow = pure
  {-# INLINE prettyShow #-}

instance PrettyShow Char where
  prettyShow = pure . T.pack . pure
  {-# INLINE prettyShow #-}

  prettyShowList = pure . T.pack
  {-# INLINE prettyShowList #-}

instance PrettyShow PShowing where
  prettyShow = id
  {-# INLINE prettyShow #-}

  prettyShowList lst = do
    env <- ask
    pure $ mconcat $ fmap (`runReader` env) lst

data TermSGR = TermSGR
  { tMods  :: [TermMod]
  , tColor :: TermColor
  }
  deriving (Read, Show, Eq)

data TermMod = MReset | MBold | MFaint | MItalic | MUnderline | MSBlink
             | MRBlink | MReverse | MConceal | MCrossout | MFontP | MFont1
             | MFont2 | MFont3 | MFont4 | MFont5 | MFont6 | MFont7 | MFont8
             | MFont9 | MFont10 | MFraktur | MDblUnderline | MNormal
  deriving (Read, Show, Enum, Eq, Ord)

data TermColor = TermColor
  { tcCode   :: TermColorCode
  , tcMode   :: TermColorMode
  , tcBright :: TermColorBrightness
  } | NoColor
  deriving (Read, Show, Eq, Ord)

data TermColorCode = Black | Red | Green | Brown | Blue | Magenta | Cyan
  deriving (Read, Show, Enum, Eq, Ord)

data TermColorMode = Foreground | Background
  deriving (Read, Show, Enum, Eq, Ord)

data TermColorBrightness = Bright | Dim
  deriving (Read, Show, Enum, Eq, Ord)

(#<>) :: (PrettyShow a, PrettyShow b) => a -> b -> PShowing
a #<> b = prettyShowList [prettyShow a, prettyShow b]
infixl 5 #<>
{-# INLINE (#<>) #-}

(#*<>) :: (PrettyShow a) => a -> Text -> PShowing
a #*<> b = prettyShowList [prettyShow a, prettyShow b]
infixl 5 #*<>
{-# INLINE (#*<>) #-}

treset :: TermSGR
treset = TermSGR [MReset] NoColor
fcolor :: TermColorCode -> TermSGR
fcolor c = TermSGR [] $ TermColor c Foreground Dim
fcolorb :: TermColorCode -> TermSGR
fcolorb c = TermSGR [MBold] $ TermColor c Foreground Bright
bcolor :: TermColorCode -> TermSGR
bcolor c = TermSGR [] $ TermColor c Background Dim
bcolorb :: TermColorCode -> TermSGR
bcolorb c = TermSGR [MBold] $ TermColor c Background Bright

termGetCodes :: TermSGR -> [Int]
termGetCodes (TermSGR mods color) =
  (fromEnum <$> mods) <> case color of
                           TermColor code mode bright ->
                             [fromEnum code +
                               (case mode of
                                 Foreground -> 30
                                 Background -> 40) +
                               (case bright of
                                  Bright -> 60
                                  Dim -> 0)]
                           NoColor -> []

instance PrettyShow TermSGR where
  prettyShow tsgr = do
    env <- ask
    pure $ if hasTerm env then "\x1b[" <> T.intercalate ";" (map (T.pack . show)
                          $ termGetCodes tsgr) <> "m" else ""
