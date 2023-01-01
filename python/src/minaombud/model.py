from dataclasses import dataclass
from datetime import datetime, date
from enum import Enum
from typing import Optional, List, Any, Dict, TypeVar, Type, Collection, Sequence
from uuid import UUID

from minaombud.serialization import JSONClass


class Identitetstyp(Enum):
    PNR = "pnr"
    ORGNR = "orgnr"
    SAMNR = "samnr"
    GDNR = "gdnr"
    USERNAME = "username"


class Behorighetstyp(Enum):
    AKTIV = "aktiv"
    PASSIV = "passiv"


class FullmaktsgivareRoll(Enum):
    PRIVAT = "PRIVAT"
    ORGANISATION = "ORGANISATION"


class FullmaktStatus(Enum):
    AKTUELL = "AKTUELL"
    GILTIG = "GILTIG"
    HISTORISK = "HISTORISK"


@dataclass
class ApiError(JSONClass):
    type: str
    instance: str
    title: str
    timestamp: Optional[datetime] = None
    detail: Optional[str] = None
    status: Optional[int] = None
    request_id: Optional[str] = None


class ApiException(Exception):
    def __init__(self, *args, **kwargs):
        self.url: Optional[str] = kwargs.pop("url", None)
        self.error: ApiError = kwargs.pop("error")
        if not args:
            message = self.error.detail or self.error.title
            args = (message,)
        super(ApiException, self).__init__(*args, **kwargs)


ID = TypeVar("ID", bound="Identitetsbeteckning")


@dataclass
class Identitetsbeteckning(JSONClass):
    id: str
    typ: Identitetstyp

    @classmethod
    def from_id(cls: Type[ID], id: str, **kwargs) -> ID:
        kwargs["typ"] = classify_swedish_identity(id)
        return cls(id=id, **kwargs)


@dataclass
class Namngiven(JSONClass):
    namn: str
    fornamn: Optional[str] = None


@dataclass
class NamnIdentitet(Namngiven, Identitetsbeteckning):
    pass


@dataclass
class Fullmaktshavare(NamnIdentitet):
    pass


@dataclass
class Fullmaktsgivare(NamnIdentitet):
    pass


@dataclass
class FysiskPerson(NamnIdentitet):
    def __post_init__(self):
        if self.typ not in (Identitetstyp.PNR, Identitetstyp.SAMNR, Identitetstyp.GDNR):
            raise ValueError(
                f"Fysisk person {self.id} har ogiltig typ: {self.typ.value}"
            )


@dataclass
class JuridiskPerson(NamnIdentitet):
    def __post_init__(self):
        if self.typ != Identitetstyp.ORGNR:
            raise ValueError(
                f"Juridisk person {self.id} har ogiltig typ: {self.typ.value}"
            )


@dataclass
class JwsSig(JSONClass):
    protected: str
    signature: str
    header: Optional[Dict[str, Any]] = None


@dataclass
class UtdeladBehorighet(JSONClass):
    kod: str
    typ: Behorighetstyp
    fullmakt: str


@dataclass
class Behorighetskontext(JSONClass):
    """Behörighetskontext.

    En behörighetskontext är en unik kombination av

    * tredje man (där behörigheten gäller)
    * fullmaktsgivare (den som delat ut behörigheten)
    * fullmaktsgivarens roll (organisation eller privat)
    * en eller flera fullmaktshavare (de som får agera med behörigheten)

    Fullmaktsgivarens roll kan skilja på om en fullmaktsgivare som är
    en fysisk person representerar sin organisation (enskild näringsidkare)
    eller sig själv privat.

    Inom denna behörighetskontext finns en eller flera :class:`UtdeladBehorighet`
    som identifieras med en kod, typ av behörighet (aktiv eller passiv) samt från vilken
    fullmakt behörigheten delades ut.
    """

    tredjeman: str
    fullmaktsgivare: Fullmaktsgivare
    fullmaktsgivarroll: FullmaktsgivareRoll
    fullmaktshavare: List[Fullmaktshavare]
    behorigheter: List[UtdeladBehorighet]
    tidpunkt: str
    _sig: JwsSig


@dataclass
class PageParameters(JSONClass):
    page: Optional[int] = None
    size: Optional[int] = None
    sort: Optional[str] = None


@dataclass
class PageMetadata(JSONClass):
    size: int
    number: int
    total_elements: int
    total_pages: int


@dataclass
class HamtaBehorigheterRequest(JSONClass):
    tredjeman: str
    fullmaktshavare: Identitetsbeteckning
    fullmaktsgivare: Optional[Identitetsbeteckning] = None
    fullmaktsgivarroll: Optional[Collection[FullmaktsgivareRoll]] = None
    behorigheter: Optional[Collection[str]] = None
    page: Optional[PageParameters] = None


@dataclass
class HamtaBehorigheterResponse(JSONClass):
    kontext: List[Behorighetskontext]
    page: PageMetadata


@dataclass
class HamtaFullmakterRequest(JSONClass):
    tredjeman: Optional[Collection[str]] = None
    fullmaktshavare: Optional[Identitetsbeteckning] = None
    fullmaktsgivare: Optional[Identitetsbeteckning] = None
    fullmaktsgivarroll: Optional[Collection[FullmaktsgivareRoll]] = None
    status: Optional[FullmaktStatus] = None
    aterkallad: Optional[bool] = None
    page: Optional[PageParameters] = None


class FullmaktPart(Enum):
    FULLMAKTSHAVARE = "FULLMAKTSHAVARE"
    FULLMAKTSGIVARE = "FULLMAKTSGIVARE"
    TREDJEMAN = "TREDJEMAN"


class AterkalladFullmaktDetaljer(JSONClass):
    part: FullmaktPart
    person: NamnIdentitet
    tidpunkt: str


class FullmaktListItem(JSONClass):
    id: UUID
    tredjeman: str
    fullmaktsgivare: Fullmaktsgivare
    fullmaktsgivarroll: FullmaktsgivareRoll
    fullmaktshavare: List[Fullmaktshavare]
    rubrik: str
    giltigFrom: str
    referensnummer: str
    registreringstidpunkt: str
    status: FullmaktStatus
    giltigTom: Optional[str] = None
    aterkallad: Optional[AterkalladFullmaktDetaljer] = None


@dataclass
class HamtaFullmakterResponse(JSONClass):
    fullmakter: List[FullmaktListItem]
    page: PageMetadata


@dataclass
class Underskriftsinformation(JSONClass):
    person: FysiskPerson
    tidpunkt: str


@dataclass
class Tredjeman(JSONClass):
    id: str
    namn: str


@dataclass
class FullmaktMetadata(JSONClass):
    referensnummer: str
    registreringstidpunkt: str
    status: FullmaktStatus
    underskrifter: List[Underskriftsinformation]
    aterkallad: Optional[AterkalladFullmaktDetaljer] = None


@dataclass
class FullmaktUrsprung(JSONClass):
    mall: UUID
    fullmakt: Optional[UUID] = None


@dataclass
class FullmaktJuridiskSignatar(JSONClass):
    juridisk_person: JuridiskPerson
    foretradare: Sequence[FysiskPerson]


@dataclass
class FullmaktSignatar(JSONClass):
    fysisk_person: Optional[FysiskPerson] = None
    juridisk_signatar: Optional[FullmaktJuridiskSignatar] = None

    def __post_init__(self):
        if not self.fysisk_person and not self.juridisk_signatar:
            raise ValueError("Signatär måste vara en fysisk eller juridisk person")


@dataclass
class BehorighetTyp(JSONClass):
    typ: str
    rubrik: Optional[str] = None
    beskrivning: Optional[str] = None


@dataclass
class Behorighetsobjekt(JSONClass):
    kod: str
    typer: Sequence[BehorighetTyp]
    rubrik: Optional[str] = None


@dataclass
class Behorighet(JSONClass):
    behorighetsobjekt: Behorighetsobjekt


@dataclass
class Fullmakt(JSONClass):
    id: UUID
    ursprung: FullmaktUrsprung
    rubrik: str
    beskrivning: str
    skapare: NamnIdentitet
    tredjeman: Tredjeman
    fullmaktsgivare: Fullmaktsgivare
    fullmaktsgivarroll: FullmaktsgivareRoll
    fullmaktshavare: Sequence[Fullmaktshavare]
    signatarer: Sequence[FullmaktSignatar]
    behorigheter: Sequence[Behorighet]
    giltig_from: date
    transportfullmakt: bool = False
    giltig_tom: Optional[date] = None


@dataclass
class FullmaktMetadataResponse(JSONClass):
    fullmakt: Fullmakt
    metadata: FullmaktMetadata
    svarstidpunkt: str
    _sig: JwsSig


def classify_swedish_identity(s: str) -> Identitetstyp:
    if s.startswith("16") and len(s) == 12:
        s = s[2:]
    if len(s) == 10:
        if s.startswith("302"):
            return Identitetstyp.GDNR

        if s[2] >= "2":
            return Identitetstyp.ORGNR
    elif len(s) == 12 and (s.startswith("19") or s.startswith("20")):
        if s[6] >= "6":
            return Identitetstyp.SAMNR
        else:
            return Identitetstyp.PNR

    raise ValueError(f"Invalid identification number: {s}")
