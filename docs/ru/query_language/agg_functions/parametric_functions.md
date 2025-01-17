# Параметрические агрегатные функции {#aggregate_functions_parametric}

Некоторые агрегатные функции могут принимать не только столбцы-аргументы (по которым производится свёртка), но и набор параметров - констант для инициализации. Синтаксис - две пары круглых скобок вместо одной. Первая - для параметров, вторая - для аргументов.

## histogram

Рассчитывает адаптивную гистограмму. Не гарантирует точного результата.

```
histogram(number_of_bins)(values)
```
 
Функция использует [A Streaming Parallel Decision Tree Algorithm](http://jmlr.org/papers/volume11/ben-haim10a/ben-haim10a.pdf). Границы столбцов устанавливаются по мере поступления новых данных в функцию. В общем случае столбцы имею разную ширину.

**Параметры**

`number_of_bins` — максимальное количество корзин в гистограмме. Функция автоматически вычисляет количество корзин. Она пытается получить указанное количество корзин, но если не получилось, то в результате корзин будет меньше.
`values` — [выражение](../syntax.md#syntax-expressions), предоставляющее входные значения.

**Возвращаемые значения**

- [Массив](../../data_types/array.md) [кортежей](../../data_types/tuple.md) следующего вида:

    ```
    [(lower_1, upper_1, height_1), ... (lower_N, upper_N, height_N)]
    ```

    - `lower` — нижняя граница корзины.
    - `upper` — верхняя граница корзины.
    - `height` — количество значений в корзине.

**Пример**

```sql
SELECT histogram(5)(number + 1) 
FROM (
    SELECT * 
    FROM system.numbers 
    LIMIT 20
)
```
```text
┌─histogram(5)(plus(number, 1))───────────────────────────────────────────┐
│ [(1,4.5,4),(4.5,8.5,4),(8.5,12.75,4.125),(12.75,17,4.625),(17,20,3.25)] │
└─────────────────────────────────────────────────────────────────────────┘
```

С помощью функции [bar](../other_functions.md#function-bar) можно визуализировать гистограмму, например:

```sql
WITH histogram(5)(rand() % 100) AS hist
SELECT 
    arrayJoin(hist).3 AS height, 
    bar(height, 0, 6, 5) AS bar
FROM 
(
    SELECT *
    FROM system.numbers
    LIMIT 20
)
```
```text
┌─height─┬─bar───┐
│  2.125 │ █▋    │
│   3.25 │ ██▌   │
│  5.625 │ ████▏ │
│  5.625 │ ████▏ │
│  3.375 │ ██▌   │
└────────┴───────┘
```

В этом случае необходимо помнить, что границы корзин гистограммы не известны.

## sequenceMatch(pattern)(time, cond1, cond2, ...)

Сопоставление с образцом для цепочки событий.

`pattern` - строка, содержащая шаблон для сопоставления. Шаблон похож на регулярное выражение.

`time` - время события, тип DateTime

`cond1`, `cond2` ... - от одного до 32 аргументов типа UInt8 - признаков, было ли выполнено некоторое условие для события.

Функция собирает в оперативке последовательность событий. Затем производит проверку на соответствие этой последовательности шаблону.
Возвращает UInt8 - 0, если шаблон не подходит и 1, если шаблон подходит.

Пример: `sequenceMatch('(?1).*(?2)')(EventTime, URL LIKE '%company%', URL LIKE '%cart%')`

-   была ли цепочка событий, в которой посещение страницы с адресом, содержащим company было раньше по времени посещения страницы с адресом, содержащим cart.

Это вырожденный пример. Его можно записать с помощью других агрегатных функций:

```sql
minIf(EventTime, URL LIKE '%company%') < maxIf(EventTime, URL LIKE '%cart%').
```

Но в более сложных случаях, такого решения нет.

Синтаксис шаблонов:

`(?1)` - ссылка на условие (вместо 1 - любой номер);

`.*` - произвольное количество любых событий;

`(?t>=1800)` - условие на время;

за указанное время допускается любое количество любых событий;

вместо `>=` могут использоваться операторы `<`, `>`, `<=`;

вместо 1800 может быть любое число;

События, произошедшие в одну секунду, могут оказаться в цепочке в произвольном порядке. От этого может зависеть результат работы функции.

## sequenceCount(pattern)(time, cond1, cond2, ...)

Аналогично функции sequenceMatch, но возвращает не факт наличия цепочки событий, а UInt64 - количество найденных цепочек.
Цепочки ищутся без перекрытия. То есть, следующая цепочка может начаться только после окончания предыдущей.

## windowFunnel(window)(timestamp, cond1, cond2, cond3, ...)

Отыскивает цепочки событий в скользящем окне по времени и вычисляет максимальное количество произошедших событий из цепочки.


```sql
windowFunnel(window)(timestamp, cond1, cond2, cond3, ...)
```

**Параметры**

- `window` — ширина скользящего окна по времени в секундах.
- `timestamp` — имя столбца, содержащего отметки времени. Тип данных [Date](../../data_types/date.md), [DateTime](../../data_types/datetime.md#data_type-datetime) или [UInt*](../../data_types/int_uint.md). Заметьте, что в случает хранения меток времени в столбцах с типом `UInt64`, максимально допустимое значение соответствует ограничению для типа `Int64`, т.е. равно `2^63-1`.
- `cond1`, `cond2`... — условия или данные, описывающие цепочку событий. Тип данных — `UInt8`. Значения могут быть 0 или 1.

**Алгоритм**

- Функция отыскивает данные, на которых срабатывает первое условие из цепочки, и присваивает счетчику событий значение 1. С этого же момента начинается отсчет времени скользящего окна.
- Если в пределах окна последовательно попадаются события из цепочки, то счетчик увеличивается. Если последовательность событий нарушается, то счетчик не растёт.
- Если в данных оказалось несколько цепочек разной степени завершенности, то функция выдаст только размер самой длинной цепочки.

**Возвращаемое значение**

- Целое число. Максимальное количество последовательно сработавших условий из цепочки в пределах скользящего окна по времени. Исследуются все цепочки в выборке.

**Пример**

Определим, успевает ли пользователь за час выбрать телефон в интернет-магазине и купить его.

Зададим следующую цепочку событий:

1. Пользователь вошел в личный кабинет магазина (`eventID=1001`).
2. Пользователь ищет телефон (`eventID = 1003, product = 'phone'`).
3. Пользователь сделал заказ (`eventID = 1009`).

Чтобы узнать, как далеко пользователь `user_id` смог пройти по цепочке за час в январе 2017-го года, составим запрос:

```sql
SELECT
    level,
    count() AS c
FROM
(
    SELECT
        user_id,
        windowFunnel(3600)(timestamp, eventID = 1001, eventID = 1003 AND product = 'phone', eventID = 1009) AS level
    FROM trend_event
    WHERE (event_date >= '2017-01-01') AND (event_date <= '2017-01-31')
    GROUP BY user_id
)
GROUP BY level
ORDER BY level
```

В результате мы можем получить 0, 1, 2 или 3 в зависимости от действий пользователя.


## uniqUpTo(N)(x)

Вычисляет количество различных значений аргумента, если оно меньше или равно N.
В случае, если количество различных значений аргумента больше N, возвращает N + 1.

Рекомендуется использовать для маленьких N - до 10. Максимальное значение N - 100.

Для состояния агрегатной функции используется количество оперативки равное 1 + N \* размер одного значения байт.
Для строк запоминается некриптографический хэш, имеющий размер 8 байт. То есть, для строк вычисление приближённое.

Функция также работает для нескольких аргументов.

Работает максимально быстро за исключением патологических случаев, когда используется большое значение N и количество уникальных значений чуть меньше N.

Пример применения:

```text
Задача: показывать в отчёте только поисковые фразы, по которым было хотя бы 5 уникальных посетителей.
Решение: пишем в запросе GROUP BY SearchPhrase HAVING uniqUpTo(4)(UserID) >= 5
```

[Оригинальная статья](https://clickhouse.yandex/docs/ru/query_language/agg_functions/parametric_functions/) <!--hide-->
